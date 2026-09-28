"""Safe, stable errors crossing the HTTP boundary."""


class ApiError(Exception):
    def __init__(
        self, status: int, code: str, message: str, headers: dict[str, str] | None = None
    ) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers or {}


def unauthorized() -> ApiError:
    return ApiError(401, "unauthorized", "Authentication required", {"WWW-Authenticate": "Bearer"})
