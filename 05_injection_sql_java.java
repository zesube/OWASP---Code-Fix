import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

class UserLookup {
    public ResultSet findUserByUsername(Connection connection, String username) throws SQLException {
        String query = "SELECT id, username, email FROM users WHERE username = ?";
        PreparedStatement stmt = connection.prepareStatement(query);
        stmt.setString(1, username);
        return stmt.executeQuery();
    }
}
