# Discord Role Management Bot

A command-line Discord bot for managing server roles, users, and permissions. This bot provides both interactive and command-line interfaces for comprehensive server management.

## Features

- Role Management
  - Create new roles with custom permissions
  - Delete existing roles
  - Modify role permissions
  - Force-delete stuck roles
  - List all server roles

- User Management
  - Assign roles to users
  - Kick users
  - Ban users
  - List all server members

- Channel Management
  - Set user permissions for specific channels
  - List all server channels
  - Configure read/write/speak permissions

## Prerequisites

- Python 3.8 or higher
- discord.py library
- python-dotenv library

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd discord-role-bot
```

2. Install required packages:
```bash
pip install discord.py python-dotenv
```

3. Create a `.env` file in the project root with your Discord bot token and guild ID:
```
DISCORD_TOKEN=your_bot_token_here
GUILD_ID=your_guild_id_here
```

## Usage

### Starting the Bot

Run in interactive mode:
```bash
python Discord_Admin_Bot_CLI.py
```

Run with direct commands:
```bash
python Discord_Admin_Bot_CLI.py --command-name arguments
```

### Available Commands

- List Commands
  - `--list-roles` - Show all server roles
  - `--list-users` - Show all server members
  - `--list-channels` - Show all server channels
  - `--list-permissions` - Show available permission types

- Role Management
  - `--create-role <name> [admin|permission1,permission2,...]` - Create a new role
  - `--delete-role <role_name>` - Delete a role
  - `--force-delete-role <role_name>` - Force delete a stuck role
  - `--modify-role <role_name> <permission1,permission2,...>` - Modify role permissions
  - `--assign-role <user> <role>` - Assign role to user

- User Management
  - `--kick <user>` - Kick a user
  - `--ban <user>` - Ban a user

- Channel Management
  - `--allow-access <user> <channel> <permission_type>` - Set channel permissions
    - Permission types: read, write, speak, full, mute, none

### Examples

Create an admin role:
```bash
python Discord_Admin_Bot_CLI.py --create-role "Admin Role" admin
```

Create a moderator role with specific permissions:
```bash
python Discord_Admin_Bot_CLI.py --create-role "Moderator" kick_members,ban_members,manage_messages
```

Assign a role to a user:
```bash
python Discord_Admin_Bot_CLI.py --assign-role "Username" "Role Name"
```

Force delete a stuck role:
```bash
python Discord_Admin_Bot_CLI.py --force-delete-role "Role Name"
```

## Bot Permissions

The bot requires the following permissions to function properly:
- Administrator (recommended)
OR these specific permissions:
- Manage Roles
- Manage Channels
- Kick Members
- Ban Members
- View Channels
- Send Messages

## Troubleshooting

1. Role Hierarchy Issues
   - If you can't delete/modify roles, ensure the bot's role is positioned higher in the server settings
   - Use `--force-delete-role` for stuck roles

2. Permission Errors
   - Check the bot's permissions using the startup log
   - Ensure the bot role has the necessary permissions
   - Verify the bot's role position in the server hierarchy

3. Command Not Found
   - Make sure to use double dashes (--) before commands
   - Check command spelling and required arguments
   - Use quotes for names with spaces

## Security Notes

- Keep your `.env` file secure and never share your bot token
- Carefully manage admin role creation and assignment
- Regularly audit the bot's actions using Discord's audit log
- Consider implementing additional permission checks for sensitive commands

## Contributing

Feel free to submit issues and enhancement requests!

