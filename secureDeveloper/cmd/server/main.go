package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	_ "modernc.org/sqlite"
)

const authorizationCookieName = "authorization"

type User struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"-"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}
type RegisterRequest struct {
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type WithdrawAccountRequest struct {
	Password string `json:"password"`
}
type UserResponse struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Balance  int64  `json:"balance"`
	IsAdmin  bool   `json:"is_admin"`
}
type LoginResponse struct {
	AuthMode string       `json:"auth_mode"`
	Token    string       `json:"token"`
	User     UserResponse `json:"user"`
}
type PostView struct {
	ID          uint   `json:"id"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	OwnerID     uint   `json:"owner_id"`
	Author      string `json:"author"`
	AuthorEmail string `json:"author_email"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}
type CreatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}
type UpdatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}
type PostListResponse struct {
	Posts []PostView `json:"posts"`
}
type PostResponse struct {
	Post PostView `json:"post"`
}
type DepositRequest struct {
	Amount int64 `json:"amount"`
}
type BalanceWithdrawRequest struct {
	Amount int64 `json:"amount"`
}
type TransferRequest struct {
	ToUsername string `json:"to_username"`
	Amount     int64  `json:"amount"`
}

type Store struct {
	db *sql.DB
}
type SessionStore struct {
	tokens map[string]User
}

// PW 정책 - 숫자 포함
func hasDigit(s string) bool {
	for _, r := range s {
		if unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// 미들웨어 - 로깅
func LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		latency := time.Since(start)
		log.Printf("[SERVER-LOG] %s %s | 상태코드: %d | 처리시간: %v",
			c.Request.Method, c.Request.URL.Path, c.Writer.Status(), latency)
	}
}

func main() {
	err := os.MkdirAll("log", 0755)
	if err != nil {
		panic("로그 폴더를 만들 수 없습니다: " + err.Error())
	}
	f, err := os.OpenFile("log/api.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic("로그 파일을 열 수 없습니다: " + err.Error())
	}
	defer f.Close()
	log.SetOutput(f)
	log.Println("Server Open!")

	store, err := openStore("./app.db", "./schema.sql", "./seed.sql")
	if err != nil {
		panic(err)
	}
	defer store.close()

	sessions := newSessionStore()

	router := gin.Default()

	router.Use(LoggerMiddleware())
	registerStaticRoutes(router)

	auth := router.Group("/api/auth")
	{
		// Todo 1: register
		auth.POST("/register", func(c *gin.Context) {
			var request RegisterRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid register request"})
				return
			}
			if len(request.Password) < 8 || hasDigit(request.Password) != true {
				c.JSON(http.StatusBadRequest, gin.H{"message": "password must be 8+ chars with at least one digit"})
				return
			}
			_, err := store.db.Exec("INSERT INTO users (username, name, email, phone, password, balance) VALUES (?, ?, ?, ?, ?, 1000)",
				request.Username, request.Name, request.Email, request.Phone, request.Password)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "registration failed"})
				return
			}
			c.JSON(http.StatusAccepted, gin.H{"message": "registration success"})
		})

		auth.POST("/login", func(c *gin.Context) {
			var request LoginRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid login request"})
				return
			}

			user, ok, err := store.findUserByUsername(request.Username)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load user"})
				return
			}
			if !ok || user.Password != request.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid credentials"})
				return
			}

			token, err := sessions.create(user)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to create session"})
				return
			}
			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(authorizationCookieName, token, 28800, "/", "", false, true)
			c.JSON(http.StatusOK, LoginResponse{
				AuthMode: "header-and-cookie",
				Token:    token,
				User:     makeUserResponse(user),
			})
		})

		// Todo 2: logout
		auth.POST("/logout", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			if _, ok := sessions.lookup(token); !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			sessions.delete(token)
			clearAuthorizationCookie(c)
			c.JSON(http.StatusOK, gin.H{"message": "logout success"})
		})

		// Todo 3: withdraw
		auth.POST("/withdraw", func(c *gin.Context) {
			var request WithdrawAccountRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			if user.Password != request.Password {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "PW 불일치@!!."})
				return
			}
			store.db.Exec("DELETE FROM users WHERE id = ?", user.ID)
			sessions.delete(token)
			clearAuthorizationCookie(c)
			c.JSON(http.StatusAccepted, gin.H{"message": "account withdrawn"})
		})
	}

	protected := router.Group("/api")
	{
		protected.GET("/me", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"user": makeUserResponse(user)})
		})

		// Todo 4: deposit
		protected.POST("/banking/deposit", func(c *gin.Context) {
			var request DepositRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid deposit request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			store.db.Exec("UPDATE users SET balance = balance + ? WHERE id = ?", request.Amount, user.ID)
			c.JSON(http.StatusOK, gin.H{"message": "deposit success"})
		})

		// Todo 5: withdraw (banking)
		protected.POST("/banking/withdraw", func(c *gin.Context) {
			var request BalanceWithdrawRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid withdraw request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			store.db.Exec("UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?", request.Amount, user.ID, request.Amount)
			c.JSON(http.StatusOK, gin.H{"message": "withdraw success"})
		})

		// Todo 6: transfer - 트랜잭션
		protected.POST("/banking/transfer", func(c *gin.Context) {
			var request TransferRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid transfer request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			tx, _ := store.db.Begin()
			defer tx.Rollback()
			res1, _ := tx.Exec("UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?", request.Amount, user.ID, request.Amount)
			res2, _ := tx.Exec("UPDATE users SET balance = balance + ? WHERE username = ?", request.Amount, request.ToUsername)

			if n1, _ := res1.RowsAffected(); n1 > 0 && res2 != nil {
				tx.Commit()
				c.JSON(http.StatusOK, gin.H{"message": "transfer success"})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"message": "transfer failed"})
			}
		})

		// Todo 7: posts - GET
		protected.GET("/posts", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if _, ok := sessions.lookup(token); ok == false {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			rows, _ := store.db.Query(`SELECT p.id, p.title, p.content, p.owner_id, u.name, u.email, p.created_at, p.updated_at FROM posts p JOIN users u ON p.owner_id = u.id ORDER BY p.id DESC`)
			defer rows.Close()
			var posts []PostView
			for rows.Next() {
				var v PostView
				rows.Scan(&v.ID, &v.Title, &v.Content, &v.OwnerID, &v.Author, &v.AuthorEmail, &v.CreatedAt, &v.UpdatedAt)
				posts = append(posts, v)
			}
			c.JSON(http.StatusOK, PostListResponse{Posts: posts})
		})

		// Todo 8: posts - POST
		protected.POST("/posts", func(c *gin.Context) {
			var request CreatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid create request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}
			now := time.Now().Format(time.RFC3339)
			store.db.Exec("INSERT INTO posts (title, content, owner_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", request.Title, request.Content, user.ID, now, now)
			c.JSON(http.StatusCreated, gin.H{"message": "post created"})
		})

		// Todo 9: posts - PUT
		protected.PUT("/posts/:id", func(c *gin.Context) {
			var request UpdatePostRequest
			if err := c.ShouldBindJSON(&request); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"message": "invalid update request"})
				return
			}

			token := tokenFromRequest(c)
			if token == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "missing authorization token"})
				return
			}
			user, ok := sessions.lookup(token)
			if !ok {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid authorization token"})
				return
			}

			res, _ := store.db.Exec("UPDATE posts SET title = ?, content = ?, updated_at = ? WHERE id = ? AND owner_id = ?",
				request.Title, request.Content, time.Now().Format(time.RFC3339), c.Param("id"), user.ID)
			if n, _ := res.RowsAffected(); n == 0 {
				c.JSON(http.StatusForbidden, gin.H{"message": "forbidden"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"message": "post updated"})
		})

		protected.GET("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			if _, ok := sessions.lookup(token); ok == false {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "login required"})
				return
			}
			postID := c.Param("id")
			var v PostView
			err := store.db.QueryRow(`
				SELECT p.id, p.title, p.content, p.owner_id, u.name, u.email, p.created_at, p.updated_at 
				FROM posts p JOIN users u ON p.owner_id = u.id 
				WHERE p.id = ?`, postID).Scan(
				&v.ID, &v.Title, &v.Content, &v.OwnerID, &v.Author, &v.AuthorEmail, &v.CreatedAt, &v.UpdatedAt,
			)

			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"message": "post not found"})
				return
			}
			c.JSON(http.StatusOK, PostResponse{Post: v})
		})

		protected.DELETE("/posts/:id", func(c *gin.Context) {
			token := tokenFromRequest(c)
			user, ok := sessions.lookup(token)
			if ok == false {
				c.JSON(http.StatusUnauthorized, gin.H{"message": "login required"})
				return
			}
			postID := c.Param("id")

			res, err := store.db.Exec("DELETE FROM posts WHERE id = ? AND owner_id = ?", postID, user.ID)

			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "delete failed"})
				return
			}
			count, _ := res.RowsAffected()
			if count == 0 {
				c.JSON(http.StatusForbidden, gin.H{"message": "no permission or post not found"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "post deleted success"})
		})

	}

	if err := router.Run(":8089"); err != nil {
		panic(err)
	}
}

// 스토어 및 핸들러 참고
func openStore(databasePath, schemaFile, seedFile string) (*Store, error) {
	db, err := sql.Open("sqlite", databasePath)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)

	store := &Store{db: db}
	if err := store.initialize(schemaFile, seedFile); err != nil {
		_ = db.Close()
		return nil, err
	}

	return store, nil
}

func (s *Store) close() error {
	return s.db.Close()
}

func (s *Store) initialize(schemaFile, seedFile string) error {
	if err := s.execSQLFile(schemaFile); err != nil {
		return err
	}
	if err := s.execSQLFile(seedFile); err != nil {
		return err
	}
	return nil
}

func (s *Store) execSQLFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(string(content))
	return err
}

func (s *Store) findUserByUsername(username string) (User, bool, error) {
	row := s.db.QueryRow(`
		SELECT id, username, name, email, phone, password, balance, is_admin
		FROM users
		WHERE username = ?
	`, strings.TrimSpace(username))

	var user User
	var isAdmin int64
	if err := row.Scan(&user.ID, &user.Username, &user.Name, &user.Email, &user.Phone, &user.Password, &user.Balance, &isAdmin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, false, nil
		}
		return User{}, false, err
	}
	user.IsAdmin = isAdmin == 1

	return user, true, nil
}

func newSessionStore() *SessionStore {
	return &SessionStore{
		tokens: make(map[string]User),
	}
}

func (s *SessionStore) create(user User) (string, error) {
	token, err := newSessionToken()
	if err != nil {
		return "", err
	}

	s.tokens[token] = user
	return token, nil
}

func (s *SessionStore) lookup(token string) (User, bool) {
	user, ok := s.tokens[token]
	return user, ok
}

func (s *SessionStore) delete(token string) {
	delete(s.tokens, token)
}

// fe 페이지 캐싱으로 테스트에 혼동이 있어, 별도 처리없이 main에 두시면 될 것 같습니다
// registerStaticRoutes 는 정적 파일(HTML, JS, CSS)을 제공하는 라우트를 등록한다.
func registerStaticRoutes(router *gin.Engine) {
	// 브라우저 캐시 비활성화 — 정적 파일과 루트 경로에만 적용
	router.Use(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/static/") || c.Request.URL.Path == "/" {
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			c.Header("Pragma", "no-cache")
			c.Header("Expires", "0")
		}
		c.Next()
	})
	router.Static("/static", "./static")
	router.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})
}

func makeUserResponse(user User) UserResponse {
	return UserResponse{
		ID:       user.ID,
		Username: user.Username,
		Name:     user.Name,
		Email:    user.Email,
		Phone:    user.Phone,
		Balance:  user.Balance,
		IsAdmin:  user.IsAdmin,
	}
}

func clearAuthorizationCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authorizationCookieName, "", -1, "/", "", false, true)
}

func tokenFromRequest(c *gin.Context) string {
	headerValue := strings.TrimSpace(c.GetHeader("Authorization"))
	if headerValue != "" {
		return headerValue
	}

	cookieValue, err := c.Cookie(authorizationCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookieValue)
}

func newSessionToken() (string, error) {
	buffer := make([]byte, 24)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
