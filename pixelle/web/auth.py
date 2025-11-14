# Copyright (C) 2025 AIDC-AI
# This project is licensed under the MIT License (SPDX-License-identifier: MIT).

import chainlit as cl
from pixelle.settings import settings

# Use settings.enable_login to control authentication globally
if settings.enable_login:
    @cl.password_auth_callback
    def auth_callback(username: str, password: str):
        # Use credentials from settings
        if (username == settings.default_user and password == settings.default_password):
            return cl.User(
                identifier=username, metadata={"role": "user", "provider": "credentials"}
            )
        else:
            return None

