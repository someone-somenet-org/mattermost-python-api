# [Mattermost API](https://api.mattermost.com/) bindings
([Read on github](https://github.com/someone-somenet-org/mattermost-python-api))

In productive use on a 6k+ users E10 instance at https://mattermost.fsinf.at
+ Used to manage channels, users and everything.
+ Some api-endpoints are #UNTESTED.
  + Some are not handled/#NOT_IMPLEMENTED (yet).
    + Some dont seem to make any sense to ever implement at all. Why do they even exist?
    + Others may be out of scope (I cannot test E20-stuff)
+ Beware: I love to rebase git. :)


## Setup
``pip3 install --user --upgrade mattermost``


## Usage
```
import mattermost

# login
mm = mattermost.MMApi("https://mattermost.example.com/api")
mm.login("user@example.com", "my-pw")
# alternatively use a personal-access-token/bot-token.
# mm.login(bearer="my-personal-access-token")


# do stuff (print info about your user)
import pprint
pprint.pprint(mm.get_user())


# do other stuff (print info about an not-existing user)
try:
    pprint.pprint(mm.get_user("not-existing-user-id", exc=True))
except mattermost.ApiException as e:
    print(e)


# custom endpoint call (get server config)
cfg = mm._get("/v4/config")

# do something (enable plugins)
cfg["PluginSettings"]["Enable"] = True

# custom endpoint call (put server config)
mm._put("/v4/config", data=cfg)


# logout
mm.revoke_user_session()
```


### Websocket usage
```
import mattermost
import mattermost.ws

# login
mm = mattermost.MMApi("https://mattermost.example.com/api")
mm.login("user@example.com", "my-pw")


# define a websocket handler
def webs_handler(mmws, event_data):
    import pprint
    pprint.pprint(mmws)
    pprint.pprint(event_data)

# connect to websocket and start processing events
mmws = mattermost.ws.MMws(webs_handler, mm, "wss://mattermost.example.com/api/v4/websocket")
```

To close the websocket connection - there is no way to restart, create a new instance of MMws:
+ ``mmws.close_websocket()``


### Manually calling the API
Some endpoints are not handled (yet). You can manually call these endpoints. Available private functions:
+ ``_get(endpoint, raw=False, exc=False)``
+ ``_put(endpoint, data=None, exc=False)``
+ ``_post(endpoint, data=None, multipart_formdata=None, exc=False)``
+ ``_delete(endpoint, data=None, exc=False)``


### stdin2channel
You can pipe ``STDIN`` to a channel:
+ ``echo "message" | python3 -m mattermost.stdin2channel https://localhost:8065/api 'user@example.com' 'my-pw' 'channel_id'``
**This leaks your credentials to everyone on your system!** Only use this in trusted dev-envs.


## Endpoints
Ordered by https://api.mattermost.com/
<!-- grep -E "(^#\+)|(def\s+[^_])" mattermost/__init__.py | sed -nEe 's/^#\+/+/p' -e 's/^\s+def\s+([^(]+)\(self,?\s*(.*\)):?(.*$)/  + **``\1 (\2\3``**/p' -e 's/^\s+#def\s+(.*NOT_IMPLEMENTED.*$)/  + *``\1``*/' >> README.md -->
+ **LOGIN/LOGOUT**
  + **``login (login_id=None, password=None, token=None, bearer=None)``**
  + **``logout (**kwargs)``**
+ **USERS**
  + *``create_user() #NOT_IMPLEMENTED``*
  + **``get_users (in_team=None, not_in_team=None, in_channel=None, not_in_channel=None, group_constrained=None, without_team=None, sort=None, **kwargs)``**
  + **``get_users_by_ids_list (user_ids_list, **kwargs) #UNTESTED``**
  + **``get_users_by_group_channel_ids_list (group_channel_ids_list, **kwargs) #UNTESTED``**
  + **``get_users_by_usernames_list (usernames_list, **kwargs)``**
  + *``search_users() #NOT_IMPLEMENTED``*
  + *``autocomplete_users() #NOT_IMPLEMENTED``*
  + *``get_user_ids_of_known_users() #NOT_IMPLEMENTED``*
  + *``get_total_count_of_users_in_system() #NOT_IMPLEMENTED``*
  + **``get_user (user_id=None, **kwargs)``**
  + *``update_user() #NOT_IMPLEMENTED: # use patch_user``*
  + *``deactivate_user() #NOT_IMPLEMENTED``*
  + **``patch_user (user_id, props=None, **kwargs)``**
  + *``update_user_roles() #NOT_IMPLEMENTED``*
  + *``update_user_active_status() #NOT_IMPLEMENTED``*
  + *``get_user_profile_image() #NOT_IMPLEMENTED``*
  + *``set_user_profile_image() #NOT_IMPLEMENTED``*
  + *``delete_user_profile_image() #NOT_IMPLEMENTED``*
  + *``get_user_default_profile_image() #NOT_IMPLEMENTED``*
  + **``get_user_by_username (username, **kwargs)``**
  + *``reset_user_password() #NOT_IMPLEMENTED``*
  + *``update_user_mfa() #NOT_IMPLEMENTED``*
  + *``generate_user_mfa_secret() #NOT_IMPLEMENTED``*
  + **``demote_a_user (user_id, **kwargs)``**
  + **``promote_a_guest (user_id, **kwargs)``**
  + *``check_user_mfa() #NOT_IMPLEMENTED``*
  + *``update_user_password() #NOT_IMPLEMENTED``*
  + *``send_user_password_reset_mail() #NOT_IMPLEMENTED``*
  + *``get_user_by_email() #NOT_IMPLEMENTED``*
  + **``get_user_sessions (user_id=None, **kwargs)``**
  + **``revoke_user_session (user_id=None, session_id=None, **kwargs)``**
  + *``revoke_all_user_sessions() #NOT_IMPLEMENTED``*
  + *``attach_mobile_device_to_user_session() #NOT_IMPLEMENTED``*
  + *``get_user_audit() #NOT_IMPLEMENTED``*
  + *``admin_verify_user_email_() #NOT_IMPLEMENTED``*
  + *``verify_user_email_() #NOT_IMPLEMENTED``*
  + *``send_user_email_verification() #NOT_IMPLEMENTED``*
  + *``switch_user_login_method() #NOT_IMPLEMENTED``*
  + *``create_user_access_token() #NOT_IMPLEMENTED``*
  + *``get_user_access_tokens() #NOT_IMPLEMENTED``*
  + *``revoke_user_access_token() #NOT_IMPLEMENTED``*
  + *``get_user_access_token() #NOT_IMPLEMENTED``*
  + *``disable_user_access_token() #NOT_IMPLEMENTED``*
  + *``enable_user_access_token() #NOT_IMPLEMENTED``*
  + *``search_user_access_tokens() #NOT_IMPLEMENTED``*
  + *``update_user_auth_method() #NOT_IMPLEMENTED``*
  + *``record_user_action_custom_tos() #NOT_IMPLEMENTED``*
  + *``fetch_user_latest_accepted_custom_tos() #NOT_IMPLEMENTED``*
  + *``revoke_all_users_all_sessions() #NOT_IMPLEMENTED #MM, ARE YOU INSANE?!``*
+ **BOTS** #NOT_IMPLEMENTED
+ **TEAMS**
  + *``create_team() #NOT_IMPLEMENTED``*
  + **``get_teams (include_total_count=None, **kwargs)``**
  + **``get_team (team_id, **kwargs)``**
  + *``update_team() #NOT_IMPLEMENTED``*
  + *``delete_team() #NOT_IMPLEMENTED``*
  + *``patch_team() #NOT_IMPLEMENTED``*
  + *``update_team_privacy() #NOT_IMPLEMENTED``*
  + *``restore_team() #NOT_IMPLEMENTED``*
  + *``search_teams() #NOT_IMPLEMENTED``*
  + *``exists_team() #NOT_IMPLEMENTED``*
  + *``get_teams_for_user() #NOT_IMPLEMENTED``*
  + **``get_team_members (team_id, **kwargs)``**
  + **``add_user_to_team (team_id, user_id, **kwargs)``**
  + *``add_user_to_team_from_invite() #NOT_IMPLEMENTED``*
  + *``add_multiple_users_to_team() #NOT_IMPLEMENTED WHY?!``*
  + *``get_team_members_for_a_user() #NOT_IMPLEMENTED WHY NOT NAMING STUFF USEFULLY?!``*
  + **``get_team_member (team_id, user_id, **kwargs)``**
  + **``remove_user_from_team (team_id, user_id, **kwargs)``**
  + *``get_team_members_by_id() #NOT_IMPLEMENTED``*
  + *``get_team_stats() #NOT_IMPLEMENTED``*
  + *``regenerate_team_invite_id() #NOT_IMPLEMENTED``*
  + *``get_team_icon() #NOT_IMPLEMENTED``*
  + *``set_team_icon() #NOT_IMPLEMENTED``*
  + *``remove_team_icon() #NOT_IMPLEMENTED``*
  + *``update_team_members_roles() #NOT_IMPLEMENTED``*
  + **``update_team_members_scheme_roles (team_id, user_id, props, **kwargs)``**
  + *``get_team_unreads_for_user() #NOT_IMPLEMENTED``*
  + *``get_team_unreads() #NOT_IMPLEMENTED``*
  + *``invite_users_to_team_by_email() #NOT_IMPLEMENTED``*
  + **``invite_guests_to_team_by_email (team_id, guest_email, channels, message, **kwargs)``**
  + *``invalidate_invites_to_team_by_email() #NOT_IMPLEMENTED``*
  + *``import_team() #NOT_IMPLEMENTED``*
  + *``get_team_invite_info() #NOT_IMPLEMENTED``*
  + *``set_team_scheme() #NOT_IMPLEMENTED``*
  + *``get_team_members_minus_group_members() #NOT_IMPLEMENTED``*
  + **``get_team_channels (team_id, **kwargs) #This belongs here, not to channels!``**
+ **CHANNELS**
  + *``get_all_channels() #NOT_IMPLEMENTED NOT USEFUL AT ALL!``*
  + **``create_channel (team_id, name, display_name, purpose=None, header=None, chan_type="O", **kwargs)``**
  + **``create_dm_channel_with (other_user_id, **kwargs)``**
  + **``create_group_channel_with (other_user_ids_list, **kwargs) #UNTESTED``**
  + *``search_all_private_and_public_channels() #NOT_IMPLEMENTED``*
  + *``search_all_users_group_channels() #NOT_IMPLEMENTED``*
  + *``get_team_channels_by_id() #NOT_IMPLEMENTED``*
  + *``get_timezones_of_users_in_channel() #NOT_IMPLEMENTED``*
  + **``get_channel (channel_id, **kwargs)``**
  + **``update_channel (channel_id, props, **kwargs)``**
  + **``patch_channel (channel_id, props, **kwargs)``**
  + **``get_channel_posts_pinned (channel_id, **kwargs)``**
  + **``search_channel (team_id, term, **kwargs)``**
  + **``get_channel_by_name (team_id, channel_name, include_deleted=None, **kwargs)``**
  + **``get_channel_members (channel_id, **kwargs)``**
  + **``add_user_to_channel (channel_id, user_id, **kwargs)``**
  + **``get_channel_member (channel_id, user_id, **kwargs)``**
  + **``remove_user_from_channel (channel_id, user_id, **kwargs)``**
  + **``update_channel_members_scheme_roles (channel_id, user_id, props, **kwargs)``**
  + **``get_channel_memberships_for_user (user_id, team_id, **kwargs)``**
  + **``get_channels_for_user (user_id, team_id, **kwargs)``**
+ **POSTS**
  + **``create_post (channel_id, message, props=None, filepaths=None, root_id=None, **kwargs)``**
  + **``create_ephemeral_post (channel_id, message, user_id, **kwargs)``**
  + **``get_post (post_id, **kwargs)``**
  + **``delete_post (post_id, **kwargs)``**
  + **``patch_post (post_id, message=None, is_pinned=None, props=None, **kwargs)``**
  + **``get_posts_for_channel (channel_id, **kwargs)``**
+ **FILES**
  + **``upload_file (channel_id, filepath, **kwargs)``**
  + **``get_file (file_id, **kwargs)``**
+ **PREFERENCES** #NOT_IMPLEMENTED
+ **STATUS** #NOT_IMPLEMENTED
+ **EMOJI** #NOT_IMPLEMENTED
+ **REACTIONS**
  + **``create_reaction (user_id, post_id, emoji_name, **kwargs)``**
+ **WEBHOOKS**
  + **``create_outgoing_hook (team_id, display_name, trigger_words, callback_urls, channel_id=None, description=None, trigger_when=0, **kwargs)``**
  + **``list_outgoing_hooks (team_id, channel_id=None, **kwargs)``**
  + **``delete_outgoing_hook (hook_id, **kwargs)``**
+ **COMMANDS**
  + **``create_slash_command (team_id, trigger, url, **kwargs)``**
  + **``list_custom_slash_commands_for_team (team_id, **kwargs)``**
  + **``update_slash_command (data, **kwargs)``**
  + **``delete_slash_command (command_id, **kwargs)``**
+ **OPENGRAPH** #NOT_IMPLEMENTED
+ **SYSTEM** #NOT_IMPLEMENTED
+ **BRAND** #NOT_IMPLEMENTED
+ **OAUTH** #NOT_IMPLEMENTED
+ **SAML** #NOT_IMPLEMENTED
+ **LDAP** #NOT_IMPLEMENTED
+ **GROUPS** #NOT_IMPLEMENTED
+ **COMPLIANCE** #NOT_IMPLEMENTED
+ **CLUSTER** #NOT_IMPLEMENTED
+ **ELASTICSEARCH** #NOT_IMPLEMENTED
+ **BLEVE** #NOT_IMPLEMENTED
+ **DATARETENTION** #NOT_IMPLEMENTED
+ **JOBS** #NOT_IMPLEMENTED
+ **PLUGINS** #NOT_IMPLEMENTED
+ **ROLES** #NOT_IMPLEMENTED
+ **SCHEMES** #NOT_IMPLEMENTED
+ **INTEGRATION_ACTIONS**
  + **``open_dialog (trigger_id, response_url, dialog, **kwargs)``**
+ **TERMS_OF_SERVICE** #NOT_IMPLEMENTED
