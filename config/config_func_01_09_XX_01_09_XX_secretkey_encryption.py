def config_func(tools, index, device_type, device_id, config_old: {}, config_new: {}):
    """
    CANedge configuration update function
    :param tools: A collection of tools used for device configuration
    :param index: Consecutive device index (from 0)
    :param device_id: Device ID
    :param config_old: The current device configuration
    :param config_new: Default new device configuration
    :return: Update configuration
    """

    # This is an example of how to upgrade existing S3 credentials from plain to encrypted form. Note
    # that below assumes that the existing configuration holds the information in unencrypted form.
    # Devices already using encrypted credentials are skipped (no configuration returned)

    # New configuration uses same structure. The old configuration can safely be copied to the new.
    config_new = config_old

    # Only update configurations unencrypted credentials
    if config_new["connect"]["s3"]["server"]["keyformat"] == 0:

        # Set the server kpub
        config_new["general"]["security"] = {"kpub": tools.security.user_public_key_base64}

        # Encrypt the S3 secret key
        unencrypted_s3_secretkey = config_new["connect"]["s3"]["server"]["secretkey"]
        config_new["connect"]["s3"]["server"]["keyformat"] = 1
        config_new["connect"]["s3"]["server"]["secretkey"] = tools.security.encrypt_encode(unencrypted_s3_secretkey)

    return config_new
