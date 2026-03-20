-- Query examples for later implementation work.
-- The current skeleton only uses a real SQL query for login.

SELECT id, username, name, email, phone, password, balance, is_admin
FROM users
WHERE username = ?;

INSERT INTO users (username, name, email, phone, password, balance, is_admin)
VALUES (?, ?, ?, ?, ?, 0, ?);

UPDATE users
SET name = ?, email = ?, phone = ?, is_admin = ?
WHERE id = ?;

DELETE FROM users
WHERE id = ?;
