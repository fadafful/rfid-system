<?php

require_once './AuditTrail.php';
require_once './JwtConfig.php'; 


class User
{
    private $conn;
    private $table_name = "users";
    public $id;
    public $username;
    public $password;
    public $email;
    public $role_id;
    public $is_active;
    public $errors = [];

    public function __construct($db)
    {
        $this->conn = $db;
    }

    private function sanitizeInput($input)
    {
        return $input !== null ? htmlspecialchars(strip_tags($input)) : null;
    }

    public function usernameExists($username)
    {
        $query = "SELECT id FROM " . $this->table_name . " WHERE username = ?";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $username);
        $stmt->execute();
        return $stmt->rowCount() > 0;
    }

    public function emailExists($email)
    {
        $query = "SELECT id FROM " . $this->table_name . " WHERE email = ?";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $email);
        $stmt->execute();
        return $stmt->rowCount() > 0;
    }

    public function validate()
    {
        $this->errors = [];

        if (empty($this->username)) {
            $this->errors[] = "Username is required.";
        } elseif ($this->usernameExists($this->username) && empty($this->id)) {
            $this->errors[] = "A user with this username already exists.";
        }

        if (empty($this->email)) {
            $this->errors[] = "Email is required.";
        } elseif (!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            $this->errors[] = "Invalid email format.";
        } elseif ($this->emailExists($this->email) && empty($this->id)) {
            $this->errors[] = "A user with this email already exists.";
        }

        if (empty($this->password) && empty($this->id)) {
            $this->errors[] = "Password is required.";
        } elseif (!empty($this->password) && strlen($this->password) < 6) {
            $this->errors[] = "Password must be at least 6 characters long.";
        }

        if (empty($this->role_id)) {
            $this->errors[] = "Role ID is required.";
        }

        return empty($this->errors);
    }

    public function create()
    {
        if (!$this->validate()) {
            return false;
        }

        $query = "INSERT INTO " . $this->table_name . "
                  SET username = :username,
                      password = :password,
                      email = :email,
                      role_id = :role_id,
                      is_active = :is_active";

        try {
            $stmt = $this->conn->prepare($query);

            $this->username = $this->sanitizeInput($this->username);
            $this->email = $this->sanitizeInput($this->email);
            $this->password = password_hash($this->password, PASSWORD_BCRYPT);
            $this->role_id = $this->sanitizeInput($this->role_id);
            $this->is_active = $this->is_active ?? 1;

            $stmt->bindParam(":username", $this->username);
            $stmt->bindParam(":password", $this->password);
            $stmt->bindParam(":email", $this->email);
            $stmt->bindParam(":role_id", $this->role_id);
            $stmt->bindParam(":is_active", $this->is_active);

            if ($stmt->execute()) {
                $this->id = $this->conn->lastInsertId();
                return true;
            }

            $this->errors[] = "Failed to create user.";
            return false;
        } catch (PDOException $e) {
            $this->errors[] = "An error occurred while creating the user: " . $e->getMessage();
            return false;
        }
    }

    public function login($username, $password)
    {

        // Start session at the beginning of login
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $query = "SELECT id, username, password, email, role_id, is_active 
              FROM " . $this->table_name . " 
              WHERE username = ?
              LIMIT 0,1";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $username);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        // Create audit trail instance
        $auditTrail = new AuditTrail($this->conn);

        if (!$row) {
            // Log failed login attempt - invalid username
            $auditTrail->log([
                'action_type' => 'LOGIN_FAILED',
                'entity_type' => 'USER',
                'entity_id' => null,
                'additional_info' => [
                    'reason' => 'Invalid username',
                    'attempted_username' => $username,
                    'session_id' => session_id()
                ]
            ]);

            return ['success' => false, 'message' => 'Incorrect username or password'];
        }

        if (!$row['is_active']) {
            // Log failed login attempt - inactive account
            $auditTrail->log([
                'action_type' => 'LOGIN_FAILED',
                'entity_type' => 'USER',
                'entity_id' => $row['id'],
                'additional_info' => [
                    'reason' => 'Account inactive',
                    'username' => $username
                ]
            ]);

            return ['success' => false, 'message' => 'Account is not active'];
        }

        if (password_verify($password, $row['password'])) {
            // Populate user properties
            $this->id = $row['id'];
            $this->username = $row['username'];
            $this->email = $row['email'];
            $this->role_id = $row['role_id'];
            $this->is_active = $row['is_active'];

            // Fetch permissions
            $permissions = $this->getUserPermissions();

            // Generate JWT token
            $token = $this->generateJWTToken($permissions);

            // Format user data for audit in a cleaner way

            $auditUserData = [
                'session' => [
                    'login_time' => date('Y-m-d H:i:s'),
                    'login_type' => 'direct',
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
                    'platform' => $_SERVER['HTTP_USER_AGENT'] ?? null
                ],
                'user_details' => [
                    'id' => $this->id,
                    'username' => $this->username,
                    'email' => $this->email,
                    'role' => $this->getUserRole(),
                    'permissions_count' => count($permissions)
                ]
            ];

            // Log successful login
            $auditTrail->log([
                'action_type' => 'LOGIN_SUCCESS',
                'entity_type' => 'USER',
                'entity_id' => $this->id,
                'new_data' => $auditUserData
            ]);

            return [
                'success' => true,
                'token' => $token,
                'user' => [
                    'id' => $this->id,
                    'username' => $this->username,
                    'email' => $this->email,
                    'role' => $this->getUserRole(),
                    'permissions' => array_column($permissions, 'permission_name')
                ]
            ];
        }

        // Log failed login attempt - invalid password
        $auditTrail->log([
            'action_type' => 'LOGIN_FAILED',
            'entity_type' => 'USER',
            'entity_id' => $row['id'],
            'additional_info' => [
                'reason' => 'Invalid password',
                'username' => $username
            ]
        ]);

        return ['success' => false, 'message' => 'Incorrect username or password 🤭'];
    }

    public function getUserRole()
    {
        $query = "SELECT name as role_name
                  FROM roles
                  WHERE id = :role_id";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(":role_id", $this->role_id);
        $stmt->execute();

        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result ? $result['role_name'] : null;
    }


    public function getUserPermissions()
    {
        $query = "SELECT permission_name, permission_description 
                  FROM role_permissions 
                  WHERE role_id = :role_id";

        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':role_id', $this->role_id);
        $stmt->execute();

        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    private function generateJWTToken($permissions)
    {
        $role = $this->getUserRole();
        $payload = array(
            "id" => $this->id,
            "username" => $this->username,
            "email" => $this->email,
            "role" => $role,
            "permissions" => array_column($permissions, 'permission_name'),
            "is_active" => $this->is_active
        );
        return JwtConfig::generateToken($payload);
    }

    public function update()
    {
        if (!$this->validate()) {
            return false;
        }

        $query = "UPDATE " . $this->table_name . "
                  SET username = :username,
                      email = :email,
                      role_id = :role_id,
                      is_active = :is_active
                  WHERE id = :id";

        try {
            $stmt = $this->conn->prepare($query);

            $this->username = $this->sanitizeInput($this->username);
            $this->email = $this->sanitizeInput($this->email);
            $this->role_id = $this->sanitizeInput($this->role_id);
            $this->is_active = $this->sanitizeInput($this->is_active);
            $this->id = $this->sanitizeInput($this->id);

            $stmt->bindParam(":username", $this->username);
            $stmt->bindParam(":email", $this->email);
            $stmt->bindParam(":role_id", $this->role_id);
            $stmt->bindParam(":is_active", $this->is_active);
            $stmt->bindParam(":id", $this->id);

            if ($stmt->execute()) {
                return true;
            }

            $this->errors[] = "No changes were made to the user.";
            return false;
        } catch (PDOException $e) {
            $this->errors[] = "An error occurred while updating the user: " . $e->getMessage();
            return false;
        }
    }


    public function readOne()
    {
        $query = "SELECT * FROM " . $this->table_name . " WHERE id = ? LIMIT 0,1";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(1, $this->id);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($row) {
            $this->username = $row['username'];
            $this->email = $row['email'];
            $this->role_id = $row['role_id'];
            $this->is_active = $row['is_active'];
            return true;
        }
        return false;
    }
}
