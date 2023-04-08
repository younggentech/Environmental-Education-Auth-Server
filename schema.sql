-- Scheme for the auth database.
CREATE TABLE User (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(200) NOT NULL,
  email VARCHAR(200) UNIQUE NOT NULL,
  verified_email INT,
  role VARCHAR(20) CHECK(Role = "Student" or  Role = "Teacher" or Role = "TechAdmin" or Role = "School"),
  profile_pic VARCHAR(200) NOT NULL,
  password VARCHAR(255)
);

-- Table to store annulated tokens
CREATE TABLE BlackListedTokens(
    TokenHash VARCHAR(100) PRIMARY KEY,
    ExpiryTime INT
);
-- Event to delete already expired tokens daily.
CREATE EVENT IF NOT EXISTS ClearOutdatedTokens ON SCHEDULE EVERY '1' DAY STARTS CURRENT_TIMESTAMP DO DELETE FROM BlackListedTokens WHERE ExpiryTime > CURRENT_TIMESTAMP;