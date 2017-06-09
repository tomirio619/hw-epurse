/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * @author root
 */


import java.sql.*;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;


public class Database {
    private static final String DATABASE_DRIVER = "com.mysql.jdbc.Driver";
    private static final String DATABASE_URL = "jdbc:mysql://localhost:3306/epurse";
    private static final String USERNAME = "root";
    private static final String PASSWORD = "";
    private static final String MAX_POOL = "250"; // set your own limit
    private Connection connection;
    private Properties properties;

    public Database() {
        try {
            connection = connect();
            properties = getProperties();
            // Create db if it does not exist
            DatabaseMetaData dbm = connection.getMetaData();
            ResultSet tables = dbm.getTables(null, null, "Cards", null);
            if (!tables.next()) {
                System.out.println("Make sure you've added a database called 'epurse' via PHPMYADMIN before doing this.");
                setup();
            }
        } catch (Exception ex) {
            Logger.getLogger(Database.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public ResultSet executeQuery(String query) {
        ResultSet rs = null;
        try {
            if (connection != null) {
                System.out.println("Connection exists");
            }
            Statement statement = connection.createStatement();
            rs = statement.executeQuery(query);
            System.out.println("QUERY EXECUTED: " + query);
        } catch (SQLException ex) {
            Logger.getLogger(Database.class.getName()).log(Level.SEVERE, null, ex);
        }
        return rs;
    }

    public void updateQuery(String query) {
        try {
            Statement statement = connection.createStatement();
            statement.executeUpdate(query);
            System.out.println("QUERY EXECUTED: " + query);
        } catch (SQLException ex) {
            Logger.getLogger(Database.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    private Connection connect() {
        if (connection == null) {
            try {
                Class.forName(DATABASE_DRIVER);
                connection = DriverManager.getConnection(DATABASE_URL, getProperties());
                System.out.println("BACKEND STARTED");
            } catch (ClassNotFoundException | SQLException e) {
                System.out.println("No connection made: " + e);
            }
        }
        return connection;
    }

    public void disconnect() {
        if (connection != null) {
            try {
                connection.close();
                connection = null;
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    private void setup() {
        String query1 = "CREATE TABLE Cards ("
                + "card_id INT PRIMARY KEY AUTO_INCREMENT, "
                + "card_holder VARCHAR(255) NOT NULL, "
                + "public_key VARBINARY(324), "
                + "balance INT UNSIGNED, "
                + "blocked BOOL, "
                + "create_date DATETIME DEFAULT CURRENT_TIMESTAMP, "
                + "expiration_date DATETIME"
                + ");";

        String query2 = "CREATE TABLE Terminals ("
                + "terminal_id INT PRIMARY KEY AUTO_INCREMENT, "
                + "terminal_kind VARCHAR(255) NOT NULL, "
                + "public_key VARBINARY(324), "
                + "valid BOOL DEFAULT 1 "
                + ");";

        String query3 = "CREATE TABLE Transactions ("
                + "transaction_id INT PRIMARY KEY AUTO_INCREMENT, "
                + "card_id INT NOT NULL, "
                + "amount INT UNSIGNED, "
                + "old_balance INT UNSIGNED, "
                + "new_balance INT UNSIGNED, "
                + "signature VARCHAR(256), "
                + "transaction_date DATETIME DEFAULT CURRENT_TIMESTAMP "
                + ");";

        updateQuery(query1);
        updateQuery(query2);
        updateQuery(query3);
    }

    private Properties getProperties() {
        if (properties == null) {
            properties = new Properties();
            properties.setProperty("user", USERNAME);
            properties.setProperty("password", PASSWORD);
            properties.setProperty("MaxPooledStatements", MAX_POOL);
        }
        return properties;
    }
}
