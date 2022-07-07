from social_core.backends.oauth import BaseOAuth2


class EduTeamsOAuth2(BaseOAuth2):
    """eduTEAMS OpenID authentication backend"""

    name = "eduTEAMS"
    ID_KEY = "sub"
    ACCESS_TOKEN_METHOD = "POST"
    DEFAULT_SCOPE = ["openid profile email"]

    AUTHORIZATION_URL = "https://proxy.eduteams.org/saml2sp/OIDC/authorization"
    ACCESS_TOKEN_URL = "https://proxy.eduteams.org/OIDC/token"
    USER_INFO_URL = "https://proxy.eduteams.org/OIDC/userinfo"
    SCOPE_SEPARATOR = ","
    REDIRECT_STATE = False


    def get_user_id(self, details, response):
        """Return a unique ID for the current user, by default from server
        response."""
        return response.get(self.ID_KEY)

    def get_user_details(self, response):
        """Return user details from eduTEAMS account"""
        return {"username": response.get("sub"),
                "email": response.get("email") or '',
                "first_name": response.get("given_name"),
                "last_name": response.get("family_name")}

    def user_data(self, access_token, *args, **kwargs):
        """Loads user data from service"""
        return self.get_json(
             self.USER_INFO_URL,
             headers={'Authorization': f'Bearer {access_token}'}
        )

    def extra_data(self, user, uid, response, details=None, *args, **kwargs):
        """Return access_token and extra defined names to store in
        extra_data field"""
        data = super(BaseOAuth2, self).extra_data(
            user, uid, response, details, *args, **kwargs)
        return data
