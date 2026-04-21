from dataclasses import dataclass


@dataclass
class AccountUser:
    id: int
    email: str
    is_admin: bool = False

    def to_safe_dict(self):
        return {"id": self.id, "email": self.email, "is_admin": self.is_admin}


USERS = {
    1: AccountUser(id=1, email="alice@example.com"),
    2: AccountUser(id=2, email="admin@example.com", is_admin=True),
}


def get_account(requesting_user: AccountUser, user_id: int):
    is_owner = requesting_user.id == user_id
    is_admin = requesting_user.is_admin

    if not is_owner and not is_admin:
        return {"error": "Forbidden"}, 403

    user = USERS.get(user_id)
    if user is None:
        return {"error": "User not found"}, 404

    return user.to_safe_dict(), 200
