#!/usr/bin/env python3
"""
Someone's Mattermost API v4 bindings.
  Copyright (c) 2016-2021 by Someone <someone@somenet.org> (aka. Jan Vales <jan@jvales.net>)
  published under MIT-License
"""

import logging
import json
import random
import warnings

import requests

from .version import __version__

logger = logging.getLogger("mattermost")


class ApiException(Exception):
    """ if exc == True: Thrown when any status_code >=400 gets returned """


class MMApi:
    """Mattermost API v4 bindings."""

    def __init__(self, url):
        self._url = url
        self._bearer = None

        # temp/retrieved data.
        self._my_user_id = None

        # the only way to detect our session :/
        self._my_user_agent = "SomeMMApi-"+__version__+"-"+str(random.randrange(100000000000, 999999999999))
        self._headers = requests.utils.default_headers()
        self._headers.update({"User-Agent": self._headers["User-Agent"]+" "+self._my_user_agent})


    def _get(self, endpoint, params=None, raw=False, exc=True):
        """
        Do a get-request.

        Args:
            endpoint (string): API-Endpoint to call, including /v4/..., excluding /api/
            params (dict, optional): url-parameters-dict
            raw (bool, optional): return result raw (useful if it is a file download)
            exc (bool, optional): Throw exceptions if error code >= 400 (default=True. Can be disabled for backward-compatability for a while)

        Returns:
            dict: requested data.

        Raises:
            ApiException: If exc==True and a non-OK HTTP-Statuscode is received.
        """
        res = requests.get(self._url + endpoint, headers=self._headers, params=params)
        if raw:
            return res

        logger.info("[GET] %s --> %d", endpoint, res.status_code)
        logger.debug(json.dumps(json.loads(res.text), indent=4))
        if exc and res.status_code >= 400:
            raise ApiException(json.loads(res.text))

        return json.loads(res.text)


    def _put(self, endpoint, params=None, data=None, exc=True):
        """
        Do a put-request.

        Args:
            endpoint (string): API-Endpoint to call, including /v4/..., excluding /api/
            params (dict, optional): url-parameters-dict
            data (dict, optional): json-data to put, if any
            raw (bool, optional): return result raw (useful if it is a file download)
            exc (bool, optional): Throw exceptions if error code >= 400 (default=True. Can be disabled for backward-compatability for a while)

        Returns:
            dict: requested data.

        Raises:
            ApiException: If exc==True and a non-OK HTTP-Statuscode is received.
        """
        logger.debug(json.dumps(data, indent=4))
        res = requests.put(self._url + endpoint, headers=self._headers, params=params, data=json.dumps(data))
        logger.info("[PUT] %s --> %d", endpoint, res.status_code)
        logger.debug(json.dumps(json.loads(res.text), indent=4))
        if exc and res.status_code >= 400:
            raise ApiException(json.loads(res.text))

        return json.loads(res.text)


    def _post(self, endpoint, params=None, data=None, multipart_formdata=None, exc=True):
        """
        Do a post-request.

        Args:
            endpoint (string): API-Endpoint to call, including /v4/..., excluding /api/
            params (dict, optional): url-parameters-dict
            data (dict, optional): json-data to post, if any
            exc (bool, optional): Throw exceptions if error code >= 400 (default=True. Can be disabled for backward-compatability for a while)

        Returns:
            dict: requested data.

        Raises:
            ApiException: If exc==True and a non-OK HTTP-Statuscode is received.
        """
        logger.debug(json.dumps(data, indent=4))
        if data is not None:
            data = json.dumps(data)

        res = requests.post(self._url + endpoint, headers=self._headers, params=params, data=data, files=multipart_formdata)
        logger.info("[POST] %s --> %d", endpoint, res.status_code)
        logger.debug(json.dumps(json.loads(res.text), indent=4))
        if exc and res.status_code >= 400:
            raise ApiException(json.loads(res.text))

        return json.loads(res.text)


    def _delete(self, endpoint, params=None, data=None, exc=True):
        """
        Do a delete-request.

        Args:
            endpoint (string): API-Endpoint to call, including /v4/..., excluding /api/
            params (dict, optional): url-parameters-dict
            data (dict, optional): json-data to delete, if any
            exc (bool, optional): Throw exceptions if error code >= 400 (default=True. Can be disabled for backward-compatability for a while)

        Returns:
            dict: requested data.

        Raises:
            ApiException: If exc==True and a non-OK HTTP-Statuscode is received.
        """
        logger.debug(json.dumps(data, indent=4))
        res = requests.delete(self._url + endpoint, headers=self._headers, params=params, data=json.dumps(data))
        logger.info("[DELETE] %s --> %d", endpoint, res.status_code)
        logger.debug(json.dumps(json.loads(res.text), indent=4))
        if exc and res.status_code >= 400:
            raise ApiException(json.loads(res.text))

        return json.loads(res.text)


################################################
#+ **LOGIN/LOGOUT**


    # login is special - dont use helpers above. We also need login to be called, even if bearer is used, so we know out user-id and session-id.
    def login(self, login_id=None, password=None, token=None, bearer=None):
        """
        Login to the corresponding (self._url) mattermost instance.
        Use login_id and password, optionally token (totp)
        If bearer is passed this token is used instead.

        Unlike the MM-api this package requires to login() with bearer-tokens, because otherwise we cannot reliably and/or non-ugly get stuff like the user's id.
        """
        if self._bearer:
            logger.warning("Already logged in. Ignoring new attempt.")
            return None

        # note: bearer vs self._bearer
        if not bearer:
            props = {"login_id": login_id, "password": password, "token":token}
            res = requests.post(self._url + "/v4/users/login", headers=self._headers, data=json.dumps(props))

            if res.status_code != 200:
                logger.critical("User-Login failed: %d", res.status_code)
                return None

            self._bearer = str(res.headers["Token"])

        else:
            self._bearer = bearer

        logger.info("Token Bearer: %s", self._bearer)
        self._headers.update({"Authorization": "Bearer "+self._bearer})

        if bearer:
            res = requests.get(self._url + "/v4/users/me", headers=self._headers)
            if res.status_code != 200:
                logger.critical("Bearer-Login failed: %d", res.status_code)
                return None

        # also store our user_id
        ret = json.loads(res.text)
        self._my_user_id = ret["id"]
        return ret


    def logout(self, **kwargs):
        """
        This will end the session at the server and invalidate this MMApi-object.
        """
        return self._post("/v4/users/logout", **kwargs)



################################################
#+ **USERS**


    #def create_user() #NOT_IMPLEMENTED



    def get_users(self, in_team=None, not_in_team=None, in_channel=None, not_in_channel=None, group_constrained=None, without_team=None, sort=None, **kwargs):
        """
        Generator: iterates over all users. Results can be restricted based on other parameters.

        Args:
            in_team (string, optional): see MM-API doc.
            not_in_team (string, optional): see MM-API doc.
            in_channel (string, optional): see MM-API doc.
            not_in_channel (string, optional): see MM-API doc.
            group_constrained (bool, optional): see MM-API doc.
            without_team (bool, optional): see MM-API doc.
            sort (string, optional): see MM-API doc.

        Returns:
            generates: One User at a time.

        Raises:
            ApiException: Passed on from lower layers.
        """
        page = 0
        while True:
            data_page = self._get("/v4/users", params={
                "page":str(page),
                "per_page":"200",
                **({"in_team": in_team} if in_team else {}),
                **({"not_in_team": not_in_team} if not_in_team else {}),
                **({"not_in_team": not_in_team} if not_in_team else {}),
                **({"in_channel": in_channel} if in_channel else {}),
                **({"not_in_channel": not_in_channel} if not_in_channel else {}),
                **({"group_constrained": group_constrained} if group_constrained else {}),
                **({"without_team": without_team} if without_team else {}),
                **({"sort": sort} if sort else {}),
            }, **kwargs)

            if data_page == []:
                break
            page += 1

            for data in data_page:
                yield data



    def get_users_by_ids_list(self, user_ids_list, **kwargs): #UNTESTED
        """
        Get a list of users based on a provided list of user ids.

        Args:
            user_ids_list (list): see MM-API doc.

        Returns:
            list: of Users.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/users/ids", data=user_ids_list, **kwargs)



    def get_users_by_group_channel_ids_list(self, group_channel_ids_list, **kwargs): #UNTESTED
        """
        Get an object containing a key per group channel id in the query and its value as a list of users members of that group channel.

        Args:
            group_channel_ids_list (list): see MM-API doc.

        Returns:
            list: of channel_ids: list of Users.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/users/group_channels", data=group_channel_ids_list, **kwargs)



    def get_users_by_usernames_list(self, usernames_list, **kwargs):
        """
        Get a list of users based on a provided list of usernames.

        Args:
            usernames_list (list): see MM-API doc.

        Returns:
            list: of Users.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/users/usernames", data=usernames_list, **kwargs)



    #def search_users() #NOT_IMPLEMENTED
    #def autocomplete_users() #NOT_IMPLEMENTED
    #def get_user_ids_of_known_users() #NOT_IMPLEMENTED
    #def get_total_count_of_users_in_system() #NOT_IMPLEMENTED



    def get_user(self, user_id=None, **kwargs):
        """
        Get a list of users based on a provided list of usernames.

        Args:
            user_id (string, optional): if not given, returns Data on calling user. (/me)

        Returns:
            dict: User.

        Raises:
            ApiException: Passed on from lower layers.
        """
        if user_id is None:
            return self._get("/v4/users/me", **kwargs)

        return self._get("/v4/users/"+user_id, **kwargs)



    #def update_user() #NOT_IMPLEMENTED: # use patch_user
    #def deactivate_user() #NOT_IMPLEMENTED



    def patch_user(self, user_id, props=None, **kwargs):
        """
        Partially update a user by providing only the fields you want to update.

        Args:
            user_id (string): User to patch.
            props (dict, optional): fields you want to update.

        Returns:
            dict: User.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._put("/v4/users/"+user_id+"/patch", data=props, **kwargs)



    #def update_user_roles() #NOT_IMPLEMENTED
    #def update_user_active_status() #NOT_IMPLEMENTED
    #def get_user_profile_image() #NOT_IMPLEMENTED
    #def set_user_profile_image() #NOT_IMPLEMENTED
    #def delete_user_profile_image() #NOT_IMPLEMENTED
    #def get_user_default_profile_image() #NOT_IMPLEMENTED



    def get_user_by_username(self, username, **kwargs):
        """
        Get a user object by providing a username.
        Sensitive information will be sanitized out.

        Args:
            username (string): User's username.

        Returns:
            dict: User.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/users/username/"+username, **kwargs)



    #def reset_user_password() #NOT_IMPLEMENTED
    #def update_user_mfa() #NOT_IMPLEMENTED
    #def generate_user_mfa_secret() #NOT_IMPLEMENTED



    def demote_a_user(self, user_id, **kwargs):
        """
        Convert a regular user into a guest.
        This will convert the user into a guest for the whole system while retaining their existing team and channel memberships.

        Args:
            user_id (string): User to demote.

        Returns:
            string: Status.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/users/"+user_id+"/demote", **kwargs)



    def promote_a_guest(self, user_id, **kwargs):
        """
        Convert a guest into a regular user.
        This will convert the guest into a user for the whole system while retaining any team and channel memberships and automatically joining them to the default channels.

        Args:
            user_id (string): User to promote   .

        Returns:
            string: Status.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/users/"+user_id+"/promote", **kwargs)



    #def check_user_mfa() #NOT_IMPLEMENTED
    #def update_user_password() #NOT_IMPLEMENTED
    #def send_user_password_reset_mail() #NOT_IMPLEMENTED
    #def get_user_by_email() #NOT_IMPLEMENTED



    def get_user_sessions(self, user_id=None, **kwargs):
        """
        Get a list of sessions by providing the user GUID. Sensitive information will be sanitized out.

        Args:
            user_id (string, optional): if not given, returns Data on logged in user. (/me)

        Returns:
            list: of dicts of Sessions.

        Raises:
            ApiException: Passed on from lower layers.
        """
        if user_id is None:
            user_id = self._my_user_id

        return self._get("/v4/users/"+user_id+"/sessions", **kwargs)



    def revoke_user_session(self, user_id=None, session_id=None, **kwargs):
        """
        Revokes a user session from the provided user id and session id strings.
        Previously this was the only way to logout.
        Please migrate to logout()

        """
        if not user_id and not session_id:
            warnings.warn("revoke_user_session() without arguments is deprecated; use logout().", category=DeprecationWarning)

        if user_id is None:
            user_id = self._my_user_id

        if session_id is None:
            session_id = self._bearer

        return self._post("/v4/users/"+user_id+"/sessions/revoke", data={"session_id": session_id}, **kwargs)



    #def revoke_all_user_sessions() #NOT_IMPLEMENTED
    #def attach_mobile_device_to_user_session() #NOT_IMPLEMENTED
    #def get_user_audit() #NOT_IMPLEMENTED
    #def admin_verify_user_email_() #NOT_IMPLEMENTED
    #def verify_user_email_() #NOT_IMPLEMENTED
    #def send_user_email_verification() #NOT_IMPLEMENTED
    #def switch_user_login_method() #NOT_IMPLEMENTED
    #def create_user_access_token() #NOT_IMPLEMENTED
    #def get_user_access_tokens() #NOT_IMPLEMENTED
    #def revoke_user_access_token() #NOT_IMPLEMENTED
    #def get_user_access_token() #NOT_IMPLEMENTED
    #def disable_user_access_token() #NOT_IMPLEMENTED
    #def enable_user_access_token() #NOT_IMPLEMENTED
    #def search_user_access_tokens() #NOT_IMPLEMENTED
    #def update_user_auth_method() #NOT_IMPLEMENTED
    #def record_user_action_custom_tos() #NOT_IMPLEMENTED
    #def fetch_user_latest_accepted_custom_tos() #NOT_IMPLEMENTED
    #def revoke_all_users_all_sessions() #NOT_IMPLEMENTED #MM, ARE YOU INSANE?!



################################################
#+ **BOTS** #NOT_IMPLEMENTED



################################################
#+ **TEAMS**



    #def create_team() #NOT_IMPLEMENTED



    def get_teams(self, include_total_count=None, **kwargs):
        """
        Generator: Get regular users only returns open teams. Users with the "manage_system" permission will return teams regardless of type.

        Args:
            include_total_count (bool, optional): see MM-API doc.

        Returns:
            generates: One Team at a time.

        Raises:
            ApiException: Passed on from lower layers.
        """
        page = 0
        while True:
            data_page = self._get("/v4/teams", params={
                "page":str(page),
                **({"include_total_count": include_total_count} if include_total_count else {}),
            }, **kwargs)

            if data_page == []:
                break
            page += 1

            for data in data_page:
                yield data



    def get_team(self, team_id, **kwargs):
        """
        Get a team on the system.

        Args:
            team_id (string): team_id.

        Returns:
            dict: Team.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/teams/"+team_id, **kwargs)



    #def update_team() #NOT_IMPLEMENTED
    #def delete_team() #NOT_IMPLEMENTED
    #def patch_team() #NOT_IMPLEMENTED
    #def update_team_privacy() #NOT_IMPLEMENTED
    #def restore_team() #NOT_IMPLEMENTED
    #def get_team_by_name() #NOT_IMPLEMENTED
    #def search_teams() #NOT_IMPLEMENTED
    #def exists_team() #NOT_IMPLEMENTED
    #def get_teams_for_user() #NOT_IMPLEMENTED



    def get_team_members(self, team_id, **kwargs):
        """
        Generator: Get a page team members list.

        Args:
            team_id (string): team_id.

        Returns:
            generates: One User at a time.

        Raises:
            ApiException: Passed on from lower layers.
        """
        page = 0
        while True:
            data_page = self._get("/v4/teams/"+team_id+"/members", params={"page":str(page)}, **kwargs)

            if data_page == []:
                break
            page += 1

            for data in data_page:
                yield data



    def add_user_to_team(self, team_id, user_id, **kwargs):
        """
        Add user to the team by user_id.

        Args:
            team_id (string): team_id to add the user to.
            user_id (string): user_id to add to team.

        Returns:
            dict: Teammembership.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/teams/"+team_id+"/members", data={
            "team_id": team_id,
            "user_id": user_id,
        }, **kwargs)



    #def add_user_to_team_from_invite() #NOT_IMPLEMENTED
    #def add_multiple_users_to_team() #NOT_IMPLEMENTED WHY?!
    #def get_team_members_for_a_user() #NOT_IMPLEMENTED WHY NOT NAMING STUFF USEFULLY?!



    def get_team_member(self, team_id, user_id, **kwargs):
        """
        Add user to the team by user_id.

        Args:
            team_id (string): team_id to add the user to.
            user_id (string): user_id to add to team.

        Returns:
            dict: Teammembership.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/teams/"+team_id+"/members/"+user_id, **kwargs)



    def remove_user_from_team(self, team_id, user_id, **kwargs):
        """
        Delete the team member object for a user, effectively removing them from a team.

        Args:
            team_id (string): team_id to remove the user from.
            user_id (string): user_id to remove.

        Returns:
            dict: status.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._delete("/v4/teams/"+team_id+"/members/"+user_id, **kwargs)



    #def get_team_members_by_id() #NOT_IMPLEMENTED
    #def get_team_stats() #NOT_IMPLEMENTED
    #def regenerate_team_invite_id() #NOT_IMPLEMENTED
    #def get_team_icon() #NOT_IMPLEMENTED
    #def set_team_icon() #NOT_IMPLEMENTED
    #def remove_team_icon() #NOT_IMPLEMENTED
    #def update_team_members_roles() #NOT_IMPLEMENTED



    def update_team_members_scheme_roles(self, team_id, user_id, props, **kwargs):
        """
        Update a team member's scheme_admin/scheme_user properties.
        Typically this should either be {scheme_admin=false, scheme_user=true} for ordinary team member, or {scheme_admin=true, scheme_user=true} for a team admin.

        Args:
            team_id (string): obvious
            user_id (string): obvious
            props (dict): see MM-API docs.

        Returns:
            dict: status.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._put("/v4/teams/"+team_id+"/members/"+user_id+"/schemeRoles", data=props, **kwargs)



    #def get_team_unreads_for_user() #NOT_IMPLEMENTED
    #def get_team_unreads() #NOT_IMPLEMENTED
    #def invite_users_to_team_by_email() #NOT_IMPLEMENTED
    #def invite_guests_to_team_by_email() #NOT_IMPLEMENTED
    #def invalidate_invites_to_team_by_email() #NOT_IMPLEMENTED
    #def import_team() #NOT_IMPLEMENTED
    #def get_team_invite_info() #NOT_IMPLEMENTED
    #def set_team_scheme() #NOT_IMPLEMENTED
    #def get_team_members_minus_group_members() #NOT_IMPLEMENTED



    def get_team_channels(self, team_id, **kwargs): #This belongs here, not to channels!
        """
        Generator: Get a page of public channels on a team.

        Args:
            team_id (string): team to get channels from.

        Returns:
            generates: Channel.

        Raises:
            ApiException: Passed on from lower layers.
        """
        page = 0
        while True:
            data_page = self._get("/v4/teams/"+team_id+"/channels", params={"page":str(page)}, **kwargs)

            if data_page == []:
                break
            page += 1

            for data in data_page:
                yield data



################################################
#+ **CHANNELS**



    #def get_all_channels() #NOT_IMPLEMENTED NOT USEFUL AT ALL!



    def create_channel(self, team_id, name, display_name, purpose=None, header=None, chan_type="O", **kwargs):
        """
        Create a new channel.

        Args:
            team_id (string): The team ID of the team to create the channel on.
            name (string): The unique handle for the channel, will be present in the channel URL.
            display_name (string): see MM-API docs.
            purpose (string, optional): see MM-API docs.
            header (string, optional): see MM-API docs.
            chan_type (string, default: public): see MM-API docs.

        Returns:
            dict: created Channel.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/channels", data={
            "team_id": team_id,
            "name": name,
            "display_name": display_name,
            **({"purpose": purpose} if purpose else {}),
            **({"header": header} if header else {}),
            "type": chan_type,
        }, **kwargs)



    def create_dm_channel_with(self, other_user_id, **kwargs):
        """
        Create a new direct message channel between two users.

        Args:
            other_user_id (string): The other user_id to create the cannel with.

        Returns:
            dict: created Channel.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/channels/direct", data=[self._my_user_id, other_user_id], **kwargs)



    def create_group_channel_with(self, other_user_ids_list, **kwargs): #UNTESTED
        """
        Create a new direct message channel between two users.

        Args:
            other_user_ids_list (list): List of user_ids to create the cannel with.

        Returns:
            dict: created Channel.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/channels/group", data=other_user_ids_list, **kwargs)



    #def search_all_private_and_public_channels() #NOT_IMPLEMENTED
    #def search_all_users_group_channels() #NOT_IMPLEMENTED
    #def get_team_channels_by_id() #NOT_IMPLEMENTED
    #def get_timezones_of_users_in_channel() #NOT_IMPLEMENTED



    def get_channel(self, channel_id, **kwargs):
        """
        Get channel from the provided channel id string.

        Args:
            channel_id (string): channel_id to get.

        Returns:
            dict: Channel.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/channels/"+channel_id, **kwargs)



    def update_channel(self, channel_id, props, **kwargs):
        """
        Update a channel. The fields that can be updated are listed as parameters. Omitted fields will be treated as blanks.

        Args:
            channel_id (string): channel_id to get.
            props (dict, optional): fields you want to update.

        Returns:
            dict: Channel.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._put("/v4/channels/"+channel_id, data=props, **kwargs)



    def patch_channel(self, channel_id, props, **kwargs):
        """
        Partially update a channel by providing only the fields you want to update. Omitted fields will not be updated. The fields that can be updated are defined in the request body, all other provided fields will be ignored.

        Args:
            channel_id (string): channel_id to get.
            props (dict, optional): fields you want to update.

        Returns:
            dict: Channel.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._put("/v4/channels/"+channel_id+"/patch", data=props, **kwargs)



    def get_channel_posts_pinned(self, channel_id, **kwargs):
        """
        Get a list of pinned posts for channel.

        Args:
            channel_id (string): channel_id to get pinned posts for.

        Returns:
            dict: Results.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/channels/"+channel_id+"/pinned", **kwargs)



    def search_channel(self, team_id, term, **kwargs):
        """
        Search public channels on a team based on the search term provided in the request body.

        Args:
            team_id (string): team_id to search in.
            term (string): The search term to match against the name or display name of channels.

        Returns:
            list: of Channels.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/teams/"+team_id+"/channels/search", data={"term": term}, **kwargs)



    def get_channel_by_name(self, team_id, channel_name, include_deleted=None, **kwargs):
        """
        Gets channel from the provided team id and channel name strings.

        Args:
            team_id (string): team_id to search in.
            term (string): The search term to match against the name or display name of channels.
            include_deleted (bool, optional): see MM-API doc.

        Returns:
            dict: Channel.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/teams/"+team_id+"/channels/name/"+channel_name, params={
            **({"include_deleted": include_deleted} if include_deleted else {}),
        }, **kwargs)



    def get_channel_members(self, channel_id, **kwargs):
        """
        Generator: Members for a channel.

        Args:
            channel_id (string): channel_id to get the members for.

        Returns:
            generates: One Member at a time.

        Raises:
            ApiException: Passed on from lower layers.
        """
        page = 0
        while True:
            data_page = self._get("/v4/channels/"+channel_id+"/members", params={"page":str(page)}, **kwargs)

            if data_page == []:
                break
            page += 1

            for data in data_page:
                yield data



    def add_user_to_channel(self, channel_id, user_id, **kwargs):
        """
        Add a user to a channel by creating a channel member object.

        Args:
            channel_id (string): channel_id to add the user to.
            user_id (string): user_id to add.

        Returns:
            dict: Membership.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/channels/"+channel_id+"/members", data={"user_id": user_id}, **kwargs)



    def get_channel_member(self, channel_id, user_id, **kwargs):
        """
        Gets channel from the provided team id and channel name strings.

        Args:
            channel_id (string): channel_id to get the members for.
            user_id (string): user_id to get the member-data for.

        Returns:
            dict: Membership.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/channels/"+channel_id+"/members/"+user_id, **kwargs)



    def remove_user_from_channel(self, channel_id, user_id, **kwargs):
        """
        Add a user to a channel by creating a channel member object.

        Args:
            channel_id (string): channel_id to remove the user from.
            user_id (string): user_id to remove.

        Returns:
            dict: status.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._delete("/v4/channels/"+channel_id+"/members/"+user_id, **kwargs)



    def update_channel_members_scheme_roles(self, channel_id, user_id, props, **kwargs):
        """
        Update a channel member's scheme_admin/scheme_user properties. Typically this should either be scheme_admin=false, scheme_user=true for ordinary channel member, or scheme_admin=true, scheme_user=true for a channel admin.

        Args:
            channel_id (string): see MM-API doc.
            user_id (string): see MM-API doc.
            props (dict): see MM-API doc.

        Returns:
            list: of Channels.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._put("/v4/channels/"+channel_id+"/members/"+user_id+"/schemeRoles", data=props, **kwargs)



    def get_channel_memberships_for_user(self, user_id, team_id, **kwargs):
        """
        Get all channel memberships and associated membership roles (i.e. channel_user, channel_admin) for a user on a specific team.

        Args:
            user_id (string): see MM-API doc.
            team_id (string): see MM-API doc.

        Returns:
            list: of Memberships.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/users/"+user_id+"/teams/"+team_id+"/channels/members", **kwargs)



    def get_channels_for_user(self, user_id, team_id, **kwargs):
        """
        Get all the channels on a team for a user.

        Args:
            user_id (string): see MM-API doc.
            team_id (string): see MM-API doc.

        Returns:
            list: of Channels.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/users/"+user_id+"/teams/"+team_id+"/channels", **kwargs)



################################################
#+ **POSTS**


    def create_post(self, channel_id, message, props=None, filepaths=None, root_id=None, **kwargs):
        """
        Create a new post in a channel. To create the post as a comment on another post, provide root_id.

        Args:
            channel_id (string): The channel ID to create the post in.
            message (string): The message text.
            props (string, optional): see MM-API docs.
            filepaths (list, optional): Paths to upload files from and attach to post.
            root_id (string, optional): see MM-API docs.

        Returns:
            dict: created Post.

        Raises:
            ApiException: Passed on from lower layers.
        """
        file_ids = []
        if filepaths:
            for filename in filepaths:
                file_ids.append(self.upload_file(channel_id, filename, **kwargs)["id"])

        return self._post("/v4/posts", data={
            "channel_id": channel_id,
            "message": message,
            **({"props": props} if props else {"props": {"from_webhook":"true"}}),
            "root_id":root_id,
            "file_ids": file_ids,
        }, **kwargs)



    def create_ephemeral_post(self, channel_id, message, user_id, **kwargs):
        """
        Create a new ephemeral post in a channel.

        Args:
            channel_id (string): The channel ID to create the post in.
            message (string): The message text.
            user_id (string): The user ID to display the post to.

        Returns:
            dict: created Post.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/posts/ephemeral", data={
            "user_id": user_id,
            "post":{
                "channel_id": channel_id,
                "message": message,
            }
        }, **kwargs)



    def get_post(self, post_id, **kwargs):
        """
        Get a single post.

        Args:
            post_id (string): The post ID to get.

        Returns:
            dict: Post.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/posts/"+post_id, **kwargs)



    def delete_post(self, post_id, **kwargs):
        """
        Soft deletes a post, by marking the post as deleted in the database. Soft deleted posts will not be returned in post queries.

        Args:
            post_id (string): The post ID to delete.

        Returns:
            string: status.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._delete("/v4/posts/"+post_id, **kwargs)



    def patch_post(self, post_id, message=None, is_pinned=None, props=None, **kwargs):
        """
        Partially update a post by providing only the fields you want to update. Omitted fields will not be updated. The fields that can be updated are defined in the request body, all other provided fields will be ignored.

        Args:
            post_id (string): The post ID to patch.
            message (string, optional): see MM-API doc.
            is_pinned (bool, optional): see MM-API doc.
            props (dict, optional): see MM-API doc.

        Returns:
            dict: Post.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._put("/v4/posts/"+post_id+"/patch", data={
            **({"message": message} if message else {}),
            **({"is_pinned": is_pinned} if is_pinned else {}),
            **({"props": props} if props else {}),
        }, **kwargs)



    def get_posts_for_channel(self, channel_id, **kwargs):
        """
        Generator: Get a page of posts in a channel. Use the query parameters to modify the behaviour of this endpoint.

        Args:
            channel_id (string): The channel ID to iterate over.

        Returns:
            generates: Post.

        Raises:
            ApiException: Passed on from lower layers.
        """
        page = 0
        while True:
            data_page = self._get("/v4/channels/"+channel_id+"/posts", params={"page":str(page)}, **kwargs)

            if data_page["order"] == []:
                break
            page += 1

            for order in data_page["order"]:
                yield data_page["posts"][order]



################################################
#+ **FILES**


    def upload_file(self, channel_id, filepath, **kwargs):
        """
        Uploads a file that can later be attached to a post.

        Args:
            channel_id (string): The channel ID to upload to.
            filepath (string): The local path of the source.

        Returns:
            dict: Uploaded File.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/files", multipart_formdata={'files':open(filepath, "rb"), "channel_id":(None, channel_id)}, **kwargs)["file_infos"][0]



    def get_file(self, file_id, **kwargs):
        """
        Uploads a file that can later be attached to a post.

        Args:
            file_id (string): The file ID to get.

        Returns:
            binary: file-content.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/files/"+file_id, raw=True, **kwargs)



################################################
#+ **PREFERENCES** #NOT_IMPLEMENTED

################################################
#+ **STATUS** #NOT_IMPLEMENTED

################################################
#+ **EMOJI** #NOT_IMPLEMENTED

################################################
#+ **REACTIONS**


    def create_reaction(self, user_id, post_id, emoji_name, **kwargs):
        """
        Create a reaction.

        Args:
            user_id (string): The ID of the user that made this reaction.
            post_id (string): The ID of the post to which this reaction was made.
            emoji_name (string): The name of the emoji that was used for this reaction.

        Returns:
            dict: created Reaction.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/reactions", data={
            "user_id": user_id,
            "post_id": post_id,
            "emoji_name": emoji_name,
        }, **kwargs)



################################################
#+ **WEBHOOKS**


    def create_outgoing_hook(self, team_id, display_name, trigger_words, callback_urls, channel_id=None, description=None, trigger_when=0, **kwargs):
        """
        Create an outgoing webhook for a team.

        Args:
            team_id (string): The ID of the team that the webhook watchs.
            display_name (string): The display name for this outgoing webhook.
            trigger_words (list): List of words for the webhook to trigger on.
            callback_urls (list): The URLs to POST the payloads to when the webhook is triggered.
            channel_id (string, optional): The ID of a public channel that the webhook watchs.
            description (string, optional): The description for this outgoing webhook.
            trigger_when (string, default int(0)): When to trigger the webhook, 0 when a trigger word is present at all and 1 if the message starts with a trigger word.

        Returns:
            dict: created Webhook.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/hooks/outgoing", data={
            "team_id": team_id,
            "display_name": display_name,
            "trigger_words": trigger_words,
            "callback_urls": callback_urls,
            **({"channel_id": channel_id} if channel_id else {}),
            **({"description": description} if description else {}),
            "trigger_when": trigger_when,
            "content_type": "application/json",
        }, **kwargs)



    def list_outgoing_hooks(self, team_id, channel_id=None, **kwargs):
        """
        Generator: Get a page of a list of outgoing webhooks. Optionally filter for a specific channel using query parameters.

        Args:
            team_id (string): The ID of the team to get hooks for.
            channel_id (string, optional): The ID of the channel to get hooks for.

        Returns:
            generates: One Webhook at a time.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/hooks/outgoing", params={
            "team_id":team_id,
            **({"channel_id": channel_id} if channel_id else {}),
        }, **kwargs)



    def delete_outgoing_hook(self, hook_id, **kwargs):
        """
        Delete an outgoing webhook given the hook id.

        Args:
            hook_id (string): The ID of the hook to delete.

        Returns:
            string: status.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._delete("/v4/hooks/outgoing/"+hook_id, **kwargs)



################################################
#+ **COMMANDS**


    def create_slash_command(self, team_id, trigger, url, **kwargs):
        """
        Create a command for a team.

        Args:
            team_id (string): Team ID to where the command should be created.
            trigger (string): Activation word to trigger the command.
            url (string): The URL that the command will make the request.

        Returns:
            dict: created Command.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/commands", data={
            "team_id": team_id,
            "trigger": trigger,
            "url": url,
            "method": "P",
        }, **kwargs)



    def list_custom_slash_commands_for_team(self, team_id, **kwargs):
        """
        List commands for a team.

        Args:
            team_id (string): The ID of the team to get hooks for.

        Returns:
            list: of Commands.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._get("/v4/commands", params={
            "team_id":team_id,
            "custom_only":True,
        }, **kwargs)



    def update_slash_command(self, data, **kwargs):
        """
        Update a single command based on command id string and Command struct.

        Args:
            data (dict): Command to update.

        Returns:
            dict: updated Command.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._put("/v4/commands/"+data["id"], data=data, **kwargs)



    def delete_slash_command(self, command_id, **kwargs):
        """
        Delete a command based on command id string.

        Args:
            command_id (string): ID of the command to delete.

        Returns:
            string: status.

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._delete("/v4/commands/"+command_id, **kwargs)



################################################
#+ **OPENGRAPH** #NOT_IMPLEMENTED

################################################
#+ **SYSTEM** #NOT_IMPLEMENTED

################################################
#+ **BRAND** #NOT_IMPLEMENTED

################################################
#+ **OAUTH** #NOT_IMPLEMENTED

################################################
#+ **SAML** #NOT_IMPLEMENTED

################################################
#+ **LDAP** #NOT_IMPLEMENTED

################################################
#+ **GROUPS** #NOT_IMPLEMENTED

################################################
#+ **COMPLIANCE** #NOT_IMPLEMENTED

################################################
#+ **CLUSTER** #NOT_IMPLEMENTED

################################################
#+ **ELASTICSEARCH** #NOT_IMPLEMENTED

################################################
#+ **BLEVE** #NOT_IMPLEMENTED

################################################
#+ **DATARETENTION** #NOT_IMPLEMENTED

################################################
#+ **JOBS** #NOT_IMPLEMENTED

################################################
#+ **PLUGINS** #NOT_IMPLEMENTED

################################################
#+ **ROLES** #NOT_IMPLEMENTED

################################################
#+ **SCHEMES** #NOT_IMPLEMENTED

################################################
#+ **INTEGRATION_ACTIONS**


    def open_dialog(self, trigger_id, response_url, dialog, **kwargs):
        """
        Open an interactive dialog using a trigger ID provided by a slash command, or some other action payload. See https://docs.mattermost.com/developer/interactive-dialogs.html for more information on interactive dialogs.

        Args:
            trigger_id (string): Trigger ID provided by other action.
            response_url (string): The URL to send the submitted dialog payload to.
            dialog (dict): Dialog definition.

        Returns:
            string: status

        Raises:
            ApiException: Passed on from lower layers.
        """
        return self._post("/v4/actions/dialogs/open", data={
            "trigger_id": trigger_id,
            "url": response_url,
            "dialog": dialog,
        }, **kwargs)



################################################
#+ **TERMS_OF_SERVICE** #NOT_IMPLEMENTED
