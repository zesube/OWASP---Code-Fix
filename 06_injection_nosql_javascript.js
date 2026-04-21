const mockUsers = [
    { username: "alice_01", email: "alice@example.com", passwordHash: "hidden", resetTokenHash: "hidden" },
    { username: "bob_admin", email: "bob@example.com", passwordHash: "hidden", resetTokenHash: "hidden" },
];

function sanitizeUser(user) {
    return {
        username: user.username,
        email: user.email,
    };
}

async function getUser(req, res) {
    try {
        const username =
            typeof req.query.username === "string" ? req.query.username.trim() : "";

        if (!/^[A-Za-z0-9_]{3,30}$/.test(username)) {
            return res.status(400).json({ error: "Invalid username." });
        }

        const user = mockUsers.find((entry) => entry.username === username) ?? null;

        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        return res.json(sanitizeUser(user));
    } catch (error) {
        return res.status(500).json({ error: "Server error." });
    }
}

module.exports = { getUser };
