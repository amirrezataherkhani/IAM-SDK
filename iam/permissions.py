import logging

from typing import Any
from django.http import HttpRequest
from rest_framework.viewsets import GenericViewSet
from rest_framework.permissions import BasePermission

from iam.exceptions import MissingValueError
from iam.validation import get_user, Authorize
from iam.schema import TokenPayload

logger = logging.Logger(__name__)


class AuthorizationBasePermission(BasePermission):
    def get_user(self, request) -> TokenPayload:
        """
        Retrieves the user information based on the provided authentication token.

        Parameters:
            request (Request): The incoming request object.

        Returns:
            TokenPayload: The user information extracted from the token.

        Raises:
            AssertionError: If the token is not set in the request headers or cookies.
        """
        token: str | None = request.headers.get("Authorization", None)
        token: str | None = token or request.COOKIES.get("Authorization", None)

        if not token:
            raise MissingValueError(detail="Token is not set", code=401, status_code=401)
        if token.lower().startswith("bearer"):
            token = token[7:]

        return get_user(token=token)

    def authorize(self, user: TokenPayload, scopes=[], roles=[]) -> TokenPayload:
        """
        Authorizes the user by checking their scopes and roles.

        Args:
            user (TokenPayload): The user to be authorized.
            scopes (list, optional): The list of scopes to check. Defaults to an empty list.
            roles (list, optional): The list of roles to check. Defaults to an empty list.

        Returns:
            TokenPayload: The authorized user.
        """
        authorizer = Authorize(scopes=scopes, roles=roles)
        authorizer.authorize(user)
        return user


class BaseAutoScopePermission(AuthorizationBasePermission):
    _service_name = None
    _object_name = None
    _action = None

    _scope = None
    _action_mapper = {
        "list": "list",
        "retrieve": "get",
        "partial_update": "update",
        "patch": "update",
        "destroy": "delete",
        "create": "create",
    }

    @property
    def scope(self) -> str:
        """
        Return the scope of the object.

        :return: The scope of the object.
        :rtype: object
        """
        if not self._scope:
            raise MissingValueError(detail="Scope is not set", code=403, status_code=403)
        return self._scope

    def set_scope(self, scope) -> None:
        """
        Set the scope of the object to the provided value.
        Example:

        ```python
        set_scope("profile:account:get")
        ```
        Parameters:
            scope (type): The new scope for the object.

        Returns:
            None
        """
        self._scope = scope

    @property
    def service_name(self) -> str:
        """
        Get the service name.
        Ensure that the service name is set and return it.

        :return: The service name.
        :rtype: str
        """
        if not self._service_name:
            raise MissingValueError(detail="Service name is not set", code=400, status_code=400)

        return self._service_name

    def set_service_name(self, service_name):
        """
        Sets the service name for the object.

        Example:
        ```python
        set_service_name("profile")
        ```

        Parameters:
            service_name (str): The name of the service.

        Returns:
            None
        """
        self._service_name = service_name

    @property
    def object_name(self) -> str:
        """
        Returns the value of the object_name property.

        :return: A string representing the object name.
        :rtype: str
        """
        if not self._service_name:
            raise MissingValueError(detail="Object name is not set", code=400, status_code=400)
        return self._object_name

    def set_object_name(self, object_name):
        """
        Set the object name.

        Parameters:
            object_name (str): The name of the object.

        Returns:
            None
        """
        self._object_name = object_name

    @property
    def action(self) -> str:
        """
        Get the value of the `action` property.

        Returns:
            str: The value of the `action` property.

        Raises:
            AssertionError: If the `action` property is not set.
        """
        if not self._action:
            raise MissingValueError(detail="Action is not set", code=400, status_code=400)
        return self._action

    def set_action(self, action):
        """
        Set the action for the object.

        Example:
        ```python
        set_action("get")
        ```
        Args:
            action: The action to set.

        Returns:
            None
        """
        self._action = action

    def generic_scope(self, object_name, action, service_name=None):
        """
        Returns the scope string for a given object name and action.

        Parameters:
            object_name (str): The name of the object.
            action (str): The action to perform on the object.
            service_name (str, optional): The name of the service. Defaults to None.

        Returns:
            str: The scope string in the format "{service_name}:{object_name}:{action}".
        """
        mapped_action = self._action_mapper.get(action, action)
        service_name = service_name or self.service_name

        return self._scope or f"{service_name}:{object_name}:{mapped_action}"


class AutoScopePermission(BaseAutoScopePermission):
    def prepare_scope(self, view) -> str:
        if isinstance(view, GenericViewSet):
            self.set_object_name(view.object_name)
            self.set_action(view.action)
            service_name = self.service_name

            scope = self.generic_scope(
                object_name=self.object_name,
                action=self.action,
                service_name=service_name,
            )
            self.set_scope(scope)

    def has_permission(self, request, view):
        self.prepare_scope(view=view)
        scope = self.scope
        user = self.get_user(request=request)

        self.authorize(user, scopes=[scope], roles=[])
        return True

    def __call__(self, *args: Any, **kwds: Any) -> Any:
        return self


def scope_permission(scope: str):
    def decorator(func):
        permission_class = AutoScopePermission()
        permission_class.set_scope(scope=scope)
        func.permission_classes = [permission_class]
        return func

    return decorator


def get_user_from_request(request: HttpRequest) -> TokenPayload | None:
    token = request.headers.get("Authorization", None)
    if not token:
        token = request.COOKIES.get("Authorization", None)
    if not token:
        return None
    token = token[7:]
    user: TokenPayload = get_user(token=token)
    return user


class IsAuthorizedUser(BasePermission):
    def has_permission(self, request, view):
        user = get_user_from_request(request)
        return user and 'user' in user.groups

