const mockUsers = new Map([
    ["507f1f77bcf86cd799439011", { id: "507f1f77bcf86cd799439011", name: "Alice", email: "alice@example.com" }],
    ["507f191e810c19729de860ea", { id: "507f191e810c19729de860ea", name: "Bob", email: "bob@example.com" }],
]);

function isValidObjectId(value) {
    return /^[a-fA-F0-9]{24}$/.test(value);
}

async function findUserById(userId) {
    return mockUsers.get(userId) ?? null;
}

async function getProfile(req, res) {
    try {
        const { userId } = req.params;

        if (!req.user) {
            return res.status(401).json({ error: "Authentication required." });
        }

        if (!isValidObjectId(userId)) {
            return res.status(400).json({ error: "Invalid user id." });
        }

        const isOwner = req.user.id === userId;
        const isAdmin = req.user.role === "admin";

        if (!isOwner && !isAdmin) {
            return res.status(403).json({ error: "Forbidden." });
        }

        const user = await findUserById(userId);
        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        return res.json({
            id: user.id,
            name: user.name,
            email: user.email,
        });
    } catch (error) {
        return res.status(500).json({ error: "Server error." });
    }
}

module.exports = { getProfile, isValidObjectId };
