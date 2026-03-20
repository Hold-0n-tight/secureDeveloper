INSERT INTO users (id, username, name, email, phone, password, balance, is_admin)
VALUES
    (1, 'alice', 'Alice Admin', 'alice.admin@example.com', '010-1111-2222', 'alice1234', 150000, 1),
    (2, 'bob', 'Bob Member', 'bob.member@example.com', '010-3333-4444', 'bob1234', 90000, 0),
    (3, 'charlie', 'Charlie Member', 'charlie.member@example.com', '010-5555-6666', 'charlie1234', 64000, 0)
ON CONFLICT(id) DO UPDATE SET
    username = excluded.username,
    name = excluded.name,
    email = excluded.email,
    phone = excluded.phone,
    password = excluded.password,
    balance = excluded.balance,
    is_admin = excluded.is_admin;
