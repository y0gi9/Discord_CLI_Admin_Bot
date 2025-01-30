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

async def create_new_role(role_name, permissions_list=None, admin=False):
    try:
        if admin:
            permissions = discord.Permissions.all()
        else:
            permissions = discord.Permissions()
            if permissions_list:
                for perm in permissions_list:
                    if hasattr(permissions, perm):
                        setattr(permissions, perm, True)
            
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
        print("Permissions enabled:", [perm[0] for perm in permissions])
        return new_role
    except discord.Forbidden:
        print("Missing permissions to create roles")
    except discord.HTTPException as e:
        print(f"Error creating role: {e}")

async def assign_role_to_user(user_identifier, role_identifier):
    member = find_member(user_identifier)
    role = find_role(role_identifier)
    
    if not member:
        print(f"User '{user_identifier}' not found")
        return
    if not role:
        print(f"Role '{role_identifier}' not found")
        return
    
    if role.is_bot_managed():
        print(f"Error: {role.name} is managed by an integration/bot")
        return
    if role.is_premium_subscriber():
        print(f"Error: {role.name} is a booster role")
        return
    
    try:
        if role.position >= bot_member.top_role.position:
            print("Attempting hierarchy adjustment...")
            
            # Create temporary role
            temp_role = await guild.create_role(
                name="Temp-Elevated-Role",
                permissions=discord.Permissions.none(),
                reason="Temporary hierarchy adjustment"
            )
            
            # Move temp role above target role
            positions = {
                temp_role: role.position + 1,
                bot_member.top_role: role.position + 2
            }
            await guild.edit_role_positions(positions=positions)
            
            # Assign role
            await member.add_roles(role)
            print(f"Successfully added role {role.name} to {member.name}")
            
            # Cleanup
            await temp_role.delete(reason="Temporary role cleanup")
        else:
            await member.add_roles(role)
            print(f"Successfully added role {role.name} to {member.name}")

    except discord.Forbidden as e:
        print("\nPermission denied. Requirements:")
        print("- Manage Roles permission")
        print("- Administrator or elevated role position")
        print(f"Discord error: {e}")
    except discord.HTTPException as e:
        print(f"Operation failed: {e}")

async def kick_user(user_identifier, reason="No reason provided"):
    member = find_member(user_identifier)
    if not member:
        print(f"User '{user_identifier}' not found")
        return

    try:
        await member.kick(reason=reason)
        print(f"Kicked {member.name}")
    except discord.Forbidden:
        print("Missing kick permissions")
    except discord.HTTPException as e:
        print(f"Kick failed: {e}")

async def ban_user(user_identifier, reason="No reason provided"):
    member = find_member(user_identifier)
    if not member:
        print(f"User '{user_identifier}' not found")
        return

    try:
        await member.ban(reason=reason, delete_message_days=0)
        print(f"Banned {member.name}")
    except discord.Forbidden:
        print("Missing ban permissions")
    except discord.HTTPException as e:
        print(f"Ban failed: {e}")

async def set_channel_permission(channel_identifier, permission_type):
    channel = find_channel(channel_identifier)
    if not channel:
        print(f"Channel '{channel_identifier}' not found")
        return

    # Get the @everyone role
    everyone_role = guild.default_role

    overwrite = discord.PermissionOverwrite()
    
    if permission_type.lower() == 'read':
        overwrite.view_channel = True
        overwrite.send_messages = False
        overwrite.connect = False
    elif permission_type.lower() == 'write':
        overwrite.view_channel = True
        overwrite.send_messages = True
        overwrite.embed_links = True
        overwrite.attach_files = True
        overwrite.add_reactions = True
    elif permission_type.lower() == 'speak':
        overwrite.view_channel = True
        overwrite.connect = True
        overwrite.speak = True
        overwrite.stream = True
        overwrite.use_voice_activation = True
    elif permission_type.lower() == 'full':
        overwrite.view_channel = True
        overwrite.send_messages = True
        overwrite.embed_links = True
        overwrite.attach_files = True
        overwrite.add_reactions = True
        overwrite.connect = True
        overwrite.speak = True
        overwrite.stream = True
        overwrite.use_voice_activation = True
    elif permission_type.lower() == 'mute':
        overwrite.view_channel = True
        overwrite.send_messages = False
        overwrite.connect = False
        overwrite.speak = False
    elif permission_type.lower() == 'none':
        overwrite.view_channel = False
    elif permission_type.lower() == 'soundboard':
        overwrite.view_channel = True
        overwrite.connect = True
        overwrite.use_soundboard = True
    else:
        print(f"Unknown permission type: {permission_type}")
        print("Available types: read, write, speak, full, mute, none, soundboard")
        return

    try:
        await channel.set_permissions(everyone_role, overwrite=overwrite)
        print(f"Updated {channel.name} permissions for everyone")
    except discord.Forbidden:
        print("Missing channel management permissions")
    except discord.HTTPException as e:
        print(f"Permission update failed: {e}")

def list_roles():
    print("\nAvailable roles:")
    for role in roles_cache:
        if role.name != "@everyone":
            managed = "[Managed]" if role.is_bot_managed() else ""
            premium = "[Booster]" if role.is_premium_subscriber() else ""
            print(f"{role.id}: {role.name} {managed}{premium} (Position: {role.position})")

def list_users():
    print("\nServer members:")
    for member in members_cache:
        print(f"{member.id}: {member.name}")

def list_channels():
    print("\nAvailable channels:")
    for channel in channels_cache:
        print(f"{channel.id}: {channel.name} ({type(channel).__name__})")

def find_channel(channel_identifier):
    try:
        channel_id = int(channel_identifier)
        return discord.utils.get(channels_cache, id=channel_id)
    except ValueError:
        return discord.utils.get(channels_cache, name=channel_identifier)

def find_member(user_identifier):
    try:
        user_id = int(user_identifier)
        return discord.utils.get(members_cache, id=user_id)
    except ValueError:
        return discord.utils.get(members_cache, name=user_identifier)

def find_role(role_identifier):
    try:
        role_id = int(role_identifier)
        return discord.utils.get(roles_cache, id=role_id)
    except ValueError:
        return discord.utils.get(roles_cache, name=role_identifier)

async def interactive_shell():
    while True:
        try:
            command = await asyncio.get_event_loop().run_in_executor(
                None, input, "\nEnter command (or 'exit' to quit): "
            )
            
            if command.lower() == 'exit':
                print("Exiting...")
                await bot.close()
                break
                
            await process_command(command.split())
            
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            await bot.close()
            break

async def process_command(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('--list-roles', action='store_true')
    parser.add_argument('--list-users', action='store_true')
    parser.add_argument('--list-channels', action='store_true')
    parser.add_argument('--create-role', nargs='+', metavar=('NAME', 'PERMS'))
    parser.add_argument('--assign-role', nargs=2, metavar=('USER', 'ROLE'))
    parser.add_argument('--kick', nargs=1, metavar='USER')
    parser.add_argument('--ban', nargs=1, metavar='USER')
    parser.add_argument('--allow-access', nargs=2, metavar=('CHANNEL', 'PERMISSION'))
    
    try:
        parsed = parser.parse_args(args)
        if parsed.list_roles:
            list_roles()
        elif parsed.list_users:
            list_users()
        elif parsed.list_channels:
            list_channels()
        elif parsed.create_role:
            role_name = parsed.create_role[0]
            if len(parsed.create_role) > 1:
                if parsed.create_role[1].lower() == 'admin':
                    await create_new_role(role_name, admin=True)
                else:
                    perms = parsed.create_role[1].split(',')
                    await create_new_role(role_name, permissions_list=perms)
            else:
                await create_new_role(role_name)
        elif parsed.assign_role:
            await assign_role_to_user(*parsed.assign_role)
        elif parsed.kick:
            await kick_user(parsed.kick[0])
        elif parsed.ban:
            await ban_user(parsed.ban[0])
        elif parsed.allow_access:
            await set_channel_permission(*parsed.allow_access)
        else:
            print("Invalid command. Use --help for usage")
    except SystemExit:
        pass

async def main():
    initial_parser = argparse.ArgumentParser()
    initial_parser.add_argument('--list-roles', action='store_true')
    initial_parser.add_argument('--list-users', action='store_true')
    initial_parser.add_argument('--list-channels', action='store_true')
    initial_parser.add_argument('--create-role', nargs='+')
    initial_parser.add_argument('--assign-role', nargs=2)
    initial_parser.add_argument('--kick', nargs=1)
    initial_parser.add_argument('--ban', nargs=1)
    initial_parser.add_argument('--allow-access', nargs=2)
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
            print("- --create-role <name> [admin|permission1,permission2,...]")
            print("Common permissions: send_messages,read_messages,connect,speak,manage_messages")
            print("- --assign-role <user> <role>")
            print("- --kick <user>")
            print("- --ban <user>")
            print("- --allow-access <channel> <permission_type>")
            print("Permission types: read, write, speak, full, mute, none, soundboard")
            print("- exit")
            await interactive_shell()

if __name__ == '__main__':
    asyncio.run(main())