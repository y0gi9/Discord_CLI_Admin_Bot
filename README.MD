# Discord Server Management Bot

A feature-rich Discord bot for server management with advanced role hierarchy handling and channel permissions control.

![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

## Features

- **Role Management**
  - Create roles with custom permissions
  - Assign roles with automatic hierarchy adjustment
  - Bypass role position limits using temporary elevation
  - List all server roles

- **User Moderation**
  - Kick/Ban members with audit logging
  - Advanced permission checks before actions

- **Channel Control**
  - Set granular permissions for @everyone
  - Enable soundboard functionality in voice channels
  - Preconfigured permission templates (read/write/speak/full)

- **Utility**
  - List server members/channels
  - Interactive command-line interface
  - Permission debugging tools

## Installation

1. **Clone Repository**
```
git clone https://github.com/y0gi9/Discord_CLI_Admin_Bot.git
cd Discord_CLI_Admin_Bot/
```
1.  **Install Dependencies**
```
pip install 
```
1.  **Configure Environment**\

    Create `.env` file:
```
DISCORD_TOKEN=your_bot_token_here
GUILD_ID=your_server_id_here
```
1.  **Set Permissions**\
    Ensure your bot has these permissions:

-   Manage Roles

-   Kick Members

-   Ban Members

-   Manage Channels

-   Administrator (for hierarchy overrides)

Usage
-----

### Command-Line Interface

# Create admin role
python bot.py --create-role Admin admin

# Assign role with hierarchy override
python bot.py --assign-role 123456789 Admin

# Enable soundboard in channel
python bot.py --allow-access 987654321 soundboard

# Kick user
python bot.py --kick 123456789

# List roles
python bot.py --list-roles

### Interactive Mode

python bot.py
> --create-role Moderator manage_messages,kick_members  
> --allow-access general-chat write  
> exit

Configuration
-------------

### Environment Variables

| Variable | Description |
| --- | --- |
| `DISCORD_TOKEN` | Bot token from Discord Developer Portal |
| `GUILD_ID` | Target server ID (right-click server icon -> Copy ID) |

### Permission Types

| Type | Description |
| --- | --- |
| `soundboard` | Enables voice channel soundboard |
| `full` | Full text+voice permissions |
| `mute` | Read-only access |
| `none` | Complete denial |

Permissions Management
----------------------

The bot handles role hierarchy automatically:

1.  Creates temporary elevated role

2.  Adjusts role positions

3.  Performs operations

4.  Cleans up temporary roles

**Required Permissions:**

-   Manage Roles

-   Administrator (for hierarchy overrides)

Troubleshooting
---------------

**Common Issues:**

-   `Missing Permissions`: Ensure bot role is above target roles

-   `Role Hierarchy`: Use `--list-roles` to check positions

-   `Channel Not Found`: Use `--list-channels` to verify IDs

-   `Temporary Role Limit`: Server must have <250 roles

Disclaimer
----------

Use this bot responsibly. The developers are not responsible for misuse. Always comply with [Discord's Terms of Service](https://discord.com/terms).

* * * * *

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/y0gi)