from starlette.exceptions import HTTPException
from rest_framework.exceptions import APIException
import typing
import http


class UnionException(APIException, HTTPException):
    def __init__(
            self,
            status_code: typing.Optional[int] = None,
            detail: typing.Optional[str] = None,
            code: typing.Optional[int] = None,
            headers: typing.Optional[dict] = None,
    ):
        if not (status_code or code):
            raise Exception(f"status_code or code is required.")

        status_code: int = status_code or code

        super().__init__(detail, status_code)

        if detail is None:
            detail = http.HTTPStatus(status_code).phrase
        self.status_code = status_code
        self.detail = detail
        self.headers = headers

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        return f"{class_name}(status_code={self.status_code!r}, detail={self.detail!r})"


class UnauthorizeException(UnionException):
    def __init__(
            self,
            status_code: int | None = 401,
            detail: str | None = "Unauthorized.",
            headers: dict | None = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class AccessDeniedException(UnionException):
    def __init__(
            self,
            status_code: int | None = 403,
            detail: str | None = "Access denied. You have not enough permissions.",
            headers: dict | None = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class TokenException(UnionException):
    def __init__(
            self,
            status_code: int | None = 400,
            detail: str | None = "Invalid token.",
            headers: dict | None = None,
    ):
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class MissingValueError(UnionException):
    def __init__(
            self,
            status_code: typing.Optional[int] = None,
            detail: typing.Optional[str] = None,
            code: typing.Optional[int] = None,
            headers: typing.Optional[dict] = None,
    ):
        super().__init__(status_code=status_code, code=code, detail=detail, headers=headers)
