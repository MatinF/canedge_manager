import re
import io
import json
from enum import Enum, IntEnum
from typing import Generator, Dict
from jsonschema import validate, ValidationError
from collections import OrderedDict
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from base64 import b64encode, b64decode
import os
import boto3


class CANedgeReturnCodes(IntEnum):
    OK = 0,
    UNKNOWN_ERROR = 1,
    CONFIG_VALIDATION_ERROR = 2,
    CONFIG_NOT_FOUND_ERROR = 3,
    UNKNOWN_DEVICE_ID_ERROR = 4,


class CANEdgeSecurity(object):

    @staticmethod
    def __gen_sym_key(device_public_key_string_xy):

        # Extract x and y from device public key
        x_bytes = device_public_key_string_xy[:32]
        y_bytes = device_public_key_string_xy[32:]
        x = int.from_bytes(x_bytes, byteorder='big')
        y = int.from_bytes(y_bytes, byteorder='big')

        # Reconstruct ECC public key
        device_pub_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        device_pub_key = device_pub_numbers.public_key(default_backend())

        # Generate user's ECC private key
        user_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        user_public_key = user_private_key.public_key()

        # Perform ECDH to generate shared secret
        shared_secret = user_private_key.exchange(ec.ECDH(), device_pub_key)

        # Derive symmetric key using HMAC-SHA256 (manually to match original logic)
        h = hmac.HMAC(shared_secret, hashes.SHA256(), backend=default_backend())
        h.update(b'config')
        digest = h.finalize()
        symmetric_key = digest[:16]  # Truncate to 128-bit AES key

        # Export user public key (raw x and y bytes)
        user_public_numbers = user_public_key.public_numbers()
        user_kpub_string_x = user_public_numbers.x.to_bytes(32, byteorder='big')
        user_kpub_string_y = user_public_numbers.y.to_bytes(32, byteorder='big')

        return symmetric_key, user_kpub_string_x + user_kpub_string_y

    def __init__(self, device_public_key_base64: str):
        self.device_public_key_base64 = device_public_key_base64
        self.device_kpub_string_xy = b64decode(self.device_public_key_base64)
        self.ksym, self.user_kpub_string_xy = self.__gen_sym_key(self.device_kpub_string_xy)

    def encrypt_encode(self, field_value: str) -> str:
        # Generate a 16-byte IV (used as nonce for CTR)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.ksym), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt
        ct = encryptor.update(field_value.encode('ascii')) + encryptor.finalize()

        # Return base64-encoded IV + ciphertext
        return b64encode(iv + ct).decode()

    @property
    def sym_key_base64(self) -> str:
        return b64encode(self.ksym).decode()

    @property
    def user_public_key_base64(self) -> str:
        if self.user_kpub_string_xy is None:
            exit("User public key not set")
        return b64encode(self.user_kpub_string_xy).decode()


class CANedgeType(str, Enum):
    UNKNOWN =   ""
    CANEDGE1 =  "0000001D"
    CANEDGE1G = "0000005D"
    CANEDGE2 =  "0000001F"
    CANEDGE2G = "0000005F"
    CANEDGE3 =  "0000003D"
    CANEDGE3G = "0000007D"


class CANedgeTools(object):

    def __init__(self, device_public_key_base64: str):
        # Create the security object, used to encrypt fields in configuration
        self._security = CANEdgeSecurity(device_public_key_base64)
        pass

    @property
    def security(self) -> CANEdgeSecurity:
        return self._security


class CANedge(object):

    __VERSION = "00.00.03"

    def __init__(self, s3_client, bucket, fw_old_path, fw_new_path=None):

        self.s3 = s3_client
        self.bucket = bucket
        self.fw_old_path = fw_old_path
        self.fw_new_path = fw_new_path if (fw_new_path is not None) else fw_old_path

        # Read fw binaries
        with open(self.fw_old_path, mode='rb') as file:
            fw_old_bin = file.read()

        with open(self.fw_new_path, mode='rb') as file:
            fw_new_bin = file.read()

        self.__fw_old = self.__parse_fw_bin(fw_old_bin)
        self.__fw_new = self.__parse_fw_bin(fw_new_bin)

        assert self.__fw_old["type"] == self.__fw_new["type"], "Firmwares not compatible"

        # Get devices matching type and schema version
        self.__devices = []
        for device in self.__s3_get_devices():
            self.__devices.append(device)
        self.__devices = sorted(self.__devices, key=lambda k: k['id'])

    def __find_device_by_id(self, device_id):
        device = list(filter(lambda x: x['id'] == device_id, self.devices))
        return device[0] if device is not None else None

    # Parse a raw binary image
    @staticmethod
    def __parse_fw_bin(fw_bin):

        fw_bin_header_pattern = fw_bin[0:4]

        type = CANedgeType.UNKNOWN
        if fw_bin_header_pattern == b"\xDE\xAD\x10\xCC":
            type = CANedgeType.CANEDGE1
        elif fw_bin_header_pattern == b"\x0F\x49\x47\xCF":
            type = CANedgeType.CANEDGE1G
        elif fw_bin_header_pattern == b"\xBA\xAD\xA5\x55":
            type = CANedgeType.CANEDGE2
        elif fw_bin_header_pattern == b"\x7F\xD4\x31\x11":
            type = CANedgeType.CANEDGE2G
        elif fw_bin_header_pattern == b"\xE6\x70\xC7\x27":
            type = CANedgeType.CANEDGE3
        elif fw_bin_header_pattern == b"\xB7\x4D\x18\x58":
            type = CANedgeType.CANEDGE3G
        else:
            assert False, "Invalid fw binary"

        # Get firmware revision
        rev_major = fw_bin[4]
        rev_minor = fw_bin[5]
        rev_patch = fw_bin[6]
        rev_string = "{:02d}.{:02d}.{:02d}".format(rev_major, rev_minor, rev_patch)

        # Get schema
        schema_name = "schema-{:02d}.{:02d}.json".format(rev_major, rev_minor)
        schema_offset = int.from_bytes(fw_bin[24:28], byteorder='big')
        schema_nob = int.from_bytes(fw_bin[28:32], byteorder='big')
        schema = fw_bin[schema_offset:schema_offset + schema_nob].decode("utf-8")

        # Get config
        config_name = "config-{:02d}.{:02d}.json".format(rev_major, rev_minor)
        config_offset = int.from_bytes(fw_bin[32:36], byteorder='big')
        config_nob = int.from_bytes(fw_bin[36:40], byteorder='big')
        config = fw_bin[config_offset:config_offset + config_nob].decode("utf-8")

        return {"type": type,
                "fw_ver": rev_string,
                "sch_name": schema_name,
                "sch": schema,
                "cfg_name": config_name,
                "cfg": config}

    def __s3_get_obj_string(self, obj_name):
        response = self.s3.get_object(Bucket=self.bucket, Key=obj_name)
        data_string = response['Body'].read().decode('ascii')
        return data_string

    def __s3_put_obj_string(self, obj_name, string):
        data = io.BytesIO(string.encode())
        self.s3.put_object(Bucket=self.bucket, Key=obj_name, Body=data)

    def __s3_get_devices(self) -> Generator[Dict, None, None]:
        """
        Fetch devices on server with matching schema name
        :return:
        """
        # List objects in the bucket
        paginator = self.s3.get_paginator('list_objects_v2')
        for result in paginator.paginate(Bucket=self.bucket):
            # Loop through objects
            for obj in result.get('Contents', []):
                r = re.search(r'^([A-F0-9]{8})/device\.json$', obj['Key'])
                if r:
                    # Load device file
                    device = json.loads(self.__s3_get_obj_string(obj['Key']))

                    # If type and schema version match, append to output
                    if (device["type"] == self.__fw_old["type"]) and (device["sch_name"] == self.__fw_old["sch_name"]):
                        yield device

    @property
    def fw(self) -> str:
        return self.__fw_old["fw_ver"]

    @property
    def fw_migration(self) -> str:
        return self.__fw_new["fw_ver"]

    @property
    def devices(self) -> []:
        return self.__devices

    @property
    def device_ids(self) -> []:
        return list((x['id'] for x in self.__devices))

    @property
    def tool_version(self) -> str:
        return self.__VERSION

    # Update configuration
    def cfg_update(self, device_ids_to_update: [str], cfg_cb, config_name=None) -> Generator[Dict, None, None]:
        """
        Updates device configuration using provided migration function
        :param device_ids_to_update:
        :param cfg_cb:
        :param config_name:
        :return: generator
        """
        # Loop devices
        for index, device_id in enumerate(device_ids_to_update):
            res = {"res": CANedgeReturnCodes.OK, "id": device_id, "msg": None}

            # Check if device id is in list of known devices
            device = self.__find_device_by_id(device_id)
            if device is None:
                res = {"res": CANedgeReturnCodes.UNKNOWN_DEVICE_ID_ERROR, "id": device_id}
                yield res
                continue

            # Get device old config
            cfg_old = self.__s3_get_obj_string(device["id"] + '/' + self.__fw_old["cfg_name"])
            # Parse json
            cfg_old_obj = json.loads(cfg_old, object_pairs_hook=OrderedDict)
            cfg_new_obj = json.loads(self.__fw_new["cfg"], object_pairs_hook=OrderedDict)

            # Create config object
            tools = CANedgeTools(device_public_key_base64=device["kpub"])

            # Get canedge type
            device_type = CANedgeType(device.get("type", ""))

            # Invoke the users migration call-back function
            cfg_updated = cfg_cb(tools, index, device_type, device_id, cfg_old_obj, cfg_new_obj)

            # Validate the new configuration against the new schema
            schema_new = json.loads(self.__fw_new["sch"])
            try:
                validate(instance=cfg_updated, schema=schema_new)
            except ValidationError as e:
                res["res"] = CANedgeReturnCodes.CONFIG_VALIDATION_ERROR
                res["msg"] = e.message
                yield res
                continue
            except Exception as e:
                res["res"] = CANedgeReturnCodes.CONFIG_VALIDATION_ERROR
                yield res
                continue

            # Push the new config
            if config_name is None:
                # If a config name is not provided, use the default name of the new fw config
                config_name = self.__fw_new["cfg_name"]
            self.__s3_put_obj_string(device["id"] + '/' + config_name, json.dumps(cfg_updated, indent=2))

            yield res

    # Clean unused configs and schemas
    def cfg_clean(self) -> Generator[Dict, None, None]:

        # Loop devices
        for device in self.devices:

            res = {"res": CANedgeReturnCodes.OK, "id": device["id"], "removed": []}

            paginator = self.s3.get_paginator('list_objects_v2')
            for result in paginator.paginate(Bucket=self.bucket, Prefix=device["id"] + '/'):
                for obj in result.get('Contents', []):

                    # Config (including the config-XX.XX.json from dry runs)
                    r = re.search(r'^[A-F0-9]{8}/(config-\w{2}\.\w{2}\.json)$', obj['Key'])
                    if r:
                        if (r[1] != self.__fw_old["cfg_name"]) and (r[1] != self.__fw_new["cfg_name"]):
                            self.s3.delete_object(Bucket=self.bucket, Key=obj['Key'])
                            res["removed"].append(r[1])

                    # Schema
                    r = re.search(r'^[A-F0-9]{8}/(schema-\d{2}\.\d{2}\.json)$', obj['Key'])
                    if r:
                        if (r[1] != self.__fw_old["sch_name"]) and (r[1] != self.__fw_new["sch_name"]):
                            self.s3.delete_object(Bucket=self.bucket, Key=obj['Key'])
                            res["removed"].append(r[1])

            yield res

    # Update firmware
    def fw_update(self, device_ids_to_update: [str]) -> Generator[Dict, None, None]:

        # Loop devices
        for device_id in device_ids_to_update:

            res = {"res": CANedgeReturnCodes.OK, "id": device_id}

            # Check if device id is in list of known devices
            device = self.__find_device_by_id(device_id)
            if device is None:
                res = {"res": CANedgeReturnCodes.UNKNOWN_DEVICE_ID_ERROR, "id": device_id}
                yield res
                continue

            # Check that a fw update is needed
            if device["fw_ver"] == self.__fw_new["fw_ver"]:
                yield res
                continue

            # Check that a valid configuration file is present
            try:
                self.s3.head_object(Bucket=self.bucket, Key=device["id"] + '/' + self.__fw_new["cfg_name"])
            except Exception as e:
                res["res"] = CANedgeReturnCodes.CONFIG_NOT_FOUND_ERROR
                yield res
                continue

            # Put firmware
            with open(self.fw_new_path, 'rb') as file:
                self.s3.upload_fileobj(file, self.bucket, device["id"] + '/firmware.bin')

            yield res