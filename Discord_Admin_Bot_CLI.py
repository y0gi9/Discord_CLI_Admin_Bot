import os
import sys
import discord
from discord.ext import commands
from dotenv import load_dotenv
import argparse
import asyncio
from datetime import datetime

# Load environment variables
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
GUILD_ID = int(os.getenv('GUILD_ID'))

intents = discord.Intents.default()
intents.members = True
intents.guilds = True
intents.message_content = True

bot = commands.Bot(command_prefix='!', intents=intents)

# Global variables
guild = None
roles_cache = []
members_cache = []
channels_cache = []
data_ready = asyncio.Event()
bot_member = None

def log_bot_permissions():
    if not guild or not bot_member:
        return
    
    permissions = bot_member.guild_permissions
    admin_status = "✅ Administrator" if permissions.administrator else "❌ Administrator"
    
    print("\n=== Bot Privileges ===")
    print(admin_status)
    print(f"Top Role: {bot_member.top_role.name} (Position: {bot_member.top_role.position})")
    print("Key Permissions:")
    print(f"- Kick Members: {permissions.kick_members}")
    print(f"- Ban Members: {permissions.ban_members}")
    print(f"- Manage Roles: {permissions.manage_roles}")
    print(f"- Manage Channels: {permissions.manage_channels}")
    print("======================")

@bot.event
async def on_ready():
    global guild, roles_cache, members_cache, channels_cache, bot_member
    print(f'{bot.user} has connected to Discord!')
    
    guild = bot.get_guild(GUILD_ID)
    if not guild:
        print(f"Guild with ID {GUILD_ID} not found")
        await bot.close()
        return

    roles_cache = await guild.fetch_roles()
    members_cache = [member async for member in guild.fetch_members(limit=None)]
    channels_cache = await guild.fetch_channels()
    bot_member = guild.get_member(bot.user.id)
    
    log_bot_permissions()
    data_ready.set()

def find_role(role_identifier):
    """Helper function to find a role by name or ID"""
    try:
        role_id = int(role_identifier)
        return discord.utils.get(roles_cache, id=role_id)
    except ValueError:
        return discord.utils.get(roles_cache, name=role_identifier)

def find_member(user_identifier):
    """Helper function to find a member by name or ID"""
    try:
        user_id = int(user_identifier)
        return discord.utils.get(members_cache, id=user_id)
    except ValueError:
        return discord.utils.get(members_cache, name=user_identifier)

def find_channel(channel_identifier):
    """Helper function to find a channel by name or ID"""
    try:
        channel_id = int(channel_identifier)
        return discord.utils.get(channels_cache, id=channel_id)
    except ValueError:
        return discord.utils.get(channels_cache, name=channel_identifier)

def list_roles():
    """List all roles in the guild"""
    print("\nServer Roles:")
    for role in sorted(roles_cache, key=lambda r: r.position, reverse=True):
        print(f"- {role.name} (ID: {role.id}, Position: {role.position})")

def list_users():
    """List all users in the guild"""
    print("\nServer Members:")
    for member in members_cache:
        roles = ', '.join(role.name for role in member.roles[1:])  # Skip @everyone
        print(f"- {member.name} (ID: {member.id})")
        if roles:
            print(f"  Roles: {roles}")

def list_channels():
    """List all channels in the guild"""
    print("\nServer Channels:")
    for channel in channels_cache:
        print(f"- {channel.name} (ID: {channel.id}, Type: {channel.type})")

# Role Management Functions
async def create_new_role(role_name, permissions_list=None, admin=False):
    try:
        if admin:
            permissions = discord.Permissions.all()
        else:
            permissions = discord.Permissions()
            if permissions_list:
                for perm in permissions_list.split(','):
                    if hasattr(permissions, perm.strip()):
                        setattr(permissions, perm.strip(), True)
            
        new_role = await guild.create_role(
            name=role_name,
            permissions=permissions,
            reason="Auto-created by bot"
        )
        
        if admin and bot_member.top_role.position > 1:
            try:
                positions = {
                    new_role: bot_member.top_role.position - 1
                }
                await guild.edit_role_positions(positions=positions)
            except discord.HTTPException:
                print("Couldn't adjust role position, but role was created")
                
        print(f"Created new role: {new_role.name} (ID: {new_role.id})")
        print("Permissions enabled:", [perm[0] for perm in permissions if perm[1]])
        return new_role
    except discord.Forbidden:
        print("Missing permissions to create roles")
    except discord.HTTPException as e:
        print(f"Error creating role: {e}")

async def delete_role(role_identifier):
    role = find_role(role_identifier)
    if not role:
        print(f"Role '{role_identifier}' not found")
        return
        
    if role.position >= bot_member.top_role.position:
        print(f"Error: Cannot delete role {role.name} as it's higher than the bot's role")
        return
        
    try:
        await role.delete()
        print(f"Successfully deleted role: {role.name}")
        # Update roles cache
        global roles_cache
        roles_cache = await guild.fetch_roles()
    except discord.Forbidden:
        print("Missing permissions to delete roles")
    except discord.HTTPException as e:
        print(f"Error deleting role: {e}")

async def force_delete_role(role_identifier):
    """Force delete a role by first moving it to the bottom of the hierarchy"""
    role = find_role(role_identifier)
    if not role:
        print(f"Role '{role_identifier}' not found")
        return
        
    try:
        # First move the role to the bottom
        positions = {
            role: 0  # Set to lowest possible position
        }
        await guild.edit_role_positions(positions=positions)
        print(f"Moved role {role.name} to bottom position")
        
        # Now delete it
        await role.delete()
        print(f"Successfully deleted role: {role.name}")
        
        # Update roles cache
        global roles_cache
        roles_cache = await guild.fetch_roles()
    except discord.Forbidden:
        print("Missing permissions to modify/delete roles")
    except discord.HTTPException as e:
        print(f"Error handling role: {e}")

async def modify_role_permissions(role_identifier, permissions_list):
    role = find_role(role_identifier)
    if not role:
        print(f"Role '{role_identifier}' not found")
        return
        
    if role.position >= bot_member.top_role.position:
        print(f"Error: Cannot modify role {role.name} as it's higher than the bot's role")
        return

    try:
        # Create new permissions object
        new_permissions = discord.Permissions()
        
        # Set new permissions
        for perm in permissions_list.split(','):
            perm = perm.strip()
            if hasattr(new_permissions, perm):
                setattr(new_permissions, perm, True)
            else:
                print(f"Warning: Unknown permission '{perm}'")
        
        # Update role
        await role.edit(permissions=new_permissions)
        print(f"Updated permissions for role: {role.name}")
        print("New permissions:", [perm[0] for perm in new_permissions if perm[1]])
        
    except discord.Forbidden:
        print("Missing permissions to modify roles")
    except discord.HTTPException as e:
        print(f"Error modifying role: {e}")

async def assign_role_to_user(user_identifier, role_identifier):
    member = find_member(user_identifier)
    if not member:
        print(f"User '{user_identifier}' not found")
        return

    role = find_role(role_identifier)
    if not role:
        print(f"Role '{role_identifier}' not found")
        return

    try:
        await member.add_roles(role)
        print(f"Successfully assigned role '{role.name}' to {member.name}")
    except discord.Forbidden:
        print("Missing permissions to assign roles")
    except discord.HTTPException as e:
        print(f"Error assigning role: {e}")

async def kick_user(user_identifier):
    member = find_member(user_identifier)
    if not member:
        print(f"User '{user_identifier}' not found")
        return

    try:
        await member.kick(reason="Kicked by bot")
        print(f"Successfully kicked {member.name}")
    except discord.Forbidden:
        print("Missing permissions to kick members")
    except discord.HTTPException as e:
        print(f"Error kicking member: {e}")

async def ban_user(user_identifier):
    member = find_member(user_identifier)
    if not member:
        print(f"User '{user_identifier}' not found")
        return

    try:
        await member.ban(reason="Banned by bot")
        print(f"Successfully banned {member.name}")
    except discord.Forbidden:
        print("Missing permissions to ban members")
    except discord.HTTPException as e:
        print(f"Error banning member: {e}")

async def set_channel_permission(user_identifier, channel_identifier, permission_type):
    member = find_member(user_identifier)
    if not member:
        print(f"User '{user_identifier}' not found")
        return

    channel = find_channel(channel_identifier)
    if not channel:
        print(f"Channel '{channel_identifier}' not found")
        return

    permission_presets = {
        'read': discord.PermissionOverwrite(view_channel=True, read_messages=True),
        'write': discord.PermissionOverwrite(send_messages=True),
        'speak': discord.PermissionOverwrite(speak=True),
        'full': discord.PermissionOverwrite(view_channel=True, send_messages=True, speak=True),
        'mute': discord.PermissionOverwrite(speak=False),
        'none': discord.PermissionOverwrite(view_channel=False)
    }

    if permission_type not in permission_presets:
        print(f"Invalid permission type. Available types: {', '.join(permission_presets.keys())}")
        return

    try:
        await channel.set_permissions(member, overwrite=permission_presets[permission_type])
        print(f"Successfully set {permission_type} permissions for {member.name} in {channel.name}")
    except discord.Forbidden:
        print("Missing permissions to modify channel permissions")
    except discord.HTTPException as e:
        print(f"Error setting permissions: {e}")

def list_available_permissions():
    print("\nAvailable Permissions:")
    # Common permission groups
    permission_groups = {
        "Text Permissions": [
            "view_channel", "send_messages", "embed_links", "attach_files",
            "read_message_history", "mention_everyone", "use_external_emojis",
            "add_reactions", "manage_messages"
        ],
        "Voice Permissions": [
            "connect", "speak", "stream", "use_voice_activation",
            "priority_speaker", "mute_members", "deafen_members", "move_members"
        ],
        "Management Permissions": [
            "kick_members", "ban_members", "manage_channels", "manage_roles",
            "manage_webhooks", "manage_emojis", "manage_events",
            "moderate_members", "view_audit_log"
        ],
        "Admin Permissions": [
            "administrator", "manage_guild", "manage_nicknames",
            "change_nickname", "view_guild_insights"
        ]
    }
    
    for group, perms in permission_groups.items():
        print(f"\n{group}:")
        for perm in perms:
            print(f"- {perm}")

async def interactive_shell():
    """Interactive command shell for the bot"""
    while True:
        try:
            command = input("\nEnter command (or 'exit' to quit): ").strip()
            if command.lower() == 'exit':
                await bot.close()
                break
            
            if command:
                await process_command(command.split())
        except Exception as e:
            print(f"Error processing command: {e}")

async def process_command(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--list-roles', action='store_true')
    parser.add_argument('--list-users', action='store_true')
    parser.add_argument('--list-channels', action='store_true')
    parser.add_argument('--list-permissions', action='store_true')
    parser.add_argument('--create-role', nargs='+', metavar=('NAME', 'PERMS'))
    parser.add_argument('--delete-role', nargs=1, metavar='ROLE')
    parser.add_argument('--modify-role', nargs=2, metavar=('ROLE', 'PERMISSIONS'))
    parser.add_argument('--assign-role', nargs=2, metavar=('USER', 'ROLE'))
    parser.add_argument('--kick', nargs=1, metavar='USER')
    parser.add_argument('--ban', nargs=1, metavar='USER')
    parser.add_argument('--allow-access', nargs=3, metavar=('USER', 'CHANNEL', 'PERMISSION'))
    parser.add_argument('--force-delete-role', nargs=1, metavar='ROLE')
    
    try:
        parsed = parser.parse_args(args)
        if parsed.list_roles:
            list_roles()
        elif parsed.list_users:
            list_users()
        elif parsed.list_channels:
            list_channels()
        elif parsed.list_permissions:
            list_available_permissions()
        elif parsed.create_role:
            role_name = parsed.create_role[0]
            if len(parsed.create_role) > 1:
                if parsed.create_role[1].lower() == 'admin':
                    await create_new_role(role_name, admin=True)
                else:
                    await create_new_role(role_name, permissions_list=parsed.create_role[1])
            else:
                await create_new_role(role_name)
        elif parsed.delete_role:
            await delete_role(parsed.delete_role[0])
        elif parsed.modify_role:
            await modify_role_permissions(*parsed.modify_role)
        elif parsed.assign_role:
            await assign_role_to_user(*parsed.assign_role)
        elif parsed.kick:
            await kick_user(parsed.kick[0])
        elif parsed.ban:
            await ban_user(parsed.ban[0])
        elif parsed.allow_access:
            await set_channel_permission(*parsed.allow_access)
        elif parsed.force_delete_role:
            await force_delete_role(parsed.force_delete_role[0])    
        else:
            print("Invalid command. Use --help for usage")
    except SystemExit:
        pass

async def main():
    initial_parser = argparse.ArgumentParser()
    initial_parser.add_argument('--list-roles', action='store_true')
    initial_parser.add_argument('--list-users', action='store_true')
    initial_parser.add_argument('--list-channels', action='store_true')
    initial_parser.add_argument('--list-permissions', action='store_true')
    initial_parser.add_argument('--create-role', nargs='+')
    initial_parser.add_argument('--delete-role', nargs=1)
    initial_parser.add_argument('--modify-role', nargs=2)
    initial_parser.add_argument('--assign-role', nargs=2)
    initial_parser.add_argument('--kick', nargs=1)
    initial_parser.add_argument('--ban', nargs=1)
    initial_parser.add_argument('--allow-access', nargs=3)
    initial_parser.add_argument('--force-delete-role', nargs=1)
    initial_args = initial_parser.parse_args()

    async with bot:
        bot_task = asyncio.create_task(bot.start(TOKEN))
        await data_ready.wait()
        
        has_initial_command = any(vars(initial_args).values())
        if has_initial_command:
            await process_command(sys.argv[1:])
            await bot.close()
        else:
            print("\nInteractive mode. Available commands:")
            print("- --list-roles")
            print("- --list-users")
            print("- --list-channels")
            print("- --list-permissions")
            print("- --create-role <name> [admin|permission1,permission2,...]")
            print("- --delete-role <role_name>")
            print("- --modify-role <role_name> <permission1,permission2,...>")
            print("- --assign-role <user> <role>")
            print("- --kick <user>")
            print("- --ban <user>")
            print("- --allow-access <user> <channel> <permission_type>")
            print("Permission types: read, write, speak, full, mute, none")
            print("- --force-delete-role <role>")
            
            print("- exit")
            await interactive_shell()

if __name__ == '__main__':
    asyncio.run(main())