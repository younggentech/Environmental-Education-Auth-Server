CREATE TABLE IF User (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(200) NOT NULL,
  email VARCHAR(200) UNIQUE NOT NULL,
  verified_email INT,
  role VARCHAR(20) CHECK(Role = "Student" or  Role = "Teacher" or Role = "TechAdmin" or Role = "School"),
  profile_pic VARCHAR(200) NOT NULL
);