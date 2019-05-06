package main

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"github.com/zenazn/goji/web/middleware"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"mdb"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"

	_ "net/http/pprof"
)

var (
	db           *sqlx.DB
	store        *sessions.CookieStore
	userStore    *mdb.UserStore
	commentStore *mdb.CommentStore
	postStore    *mdb.PostStore
)

const (
	postsPerPage   = 20
	ISO8601_FORMAT = "2006-01-02T15:04:05-07:00"
	UploadLimit    = 10 * 1024 * 1024 // 10mb

	// CSRF Token error
	StatusUnprocessableEntity = 422
)

type Post struct {
	mdb.Post
	CommentCount int
	Comments     []Comment
	User         *mdb.User
	CSRFToken    string
}

type Comment struct {
	mdb.Comment
	User *mdb.User
}

func init() {
	store = sessions.NewCookieStore([]byte("isu-app-session"))
}

func initMdbs() {
	if userStore != nil {
		userStore.Close()
	}
	userStore = mdb.NewUserStore(db)

	if commentStore != nil {
		commentStore.Close()
	}
	commentStore = mdb.NewCommentStore(db)

	if postStore != nil {
		postStore.Close()
	}
	postStore = mdb.NewPostStore(db)
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
	initMdbs()
}

func tryLogin(accountName, password string) *mdb.User {
	u, err := userStore.SelectFromName(accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	if !(regexp.MustCompile("\\A[0-9a-zA-Z_]{3,}\\z").MatchString(accountName) &&
		regexp.MustCompile("\\A[0-9a-zA-Z_]{6,}\\z").MatchString(password)) {
		return false
	}

	return true
}

// 今回のGo実装では言語側のエスケープの仕組みが使えないのでOSコマンドインジェクション対策できない
// 取り急ぎPHPのescapeshellarg関数を参考に自前で実装
// cf: http://jp2.php.net/manual/ja/function.escapeshellarg.php
func escapeshellarg(arg string) string {
	return "'" + strings.Replace(arg, "'", "'\\''", -1) + "'"
}

func digest(src string) string {
	out2 := fmt.Sprintf("%x", sha512.Sum512([]byte(src)))
	return strings.TrimSuffix(string(out2), "\n")
}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) *mdb.User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return nil
	}

	val, _ := uid.(int)
	u, err := userStore.SelectFromId(val)
	if err != nil {
		log.Print(err)
		return nil
	}

	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []*Post, CSRFToken string, allComments bool) ([]*Post, error) {
	var posts []*Post

	for _, _p := range results {
		p := *_p

		var perr error

		p.User, perr = userStore.SelectFromId(p.UserID)
		if perr != nil {
			return nil, perr
		}

		if p.User.DelFlg == 1 {
			continue
		}

		p.CommentCount = commentStore.SelectCountWherePostId(p.ID)

		limit := -1
		if !allComments {
			limit = 3
		}

		oriComments := commentStore.SelectCommentOrderByCreatedAt(p.ID, limit)

		var comments []Comment
		for _, oc := range oriComments {
			comments = append(comments, Comment{Comment: *oc})
		}

		for i := 0; i < len(comments); i++ {
			var uerr error
			comments[i].User, uerr = userStore.SelectFromId(comments[i].UserID)
			if uerr != nil {
				return nil, uerr
			}
		}

		// reverse
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}

		p.Comments = comments
		p.CSRFToken = CSRFToken

		posts = append(posts, &p)
		if len(posts) >= postsPerPage {
			break
		}
	}

	return posts, nil
}

func imageURL(p *Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u *mdb.User) bool {
	return u != nil
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := io.ReadFull(crand.Reader, k); err != nil {
		panic("error reading from random source: " + err.Error())
	}
	return hex.EncodeToString(k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("login.html")),
	).Execute(w, struct {
		Me    *mdb.User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("register.html")),
	).Execute(w, struct {
		Me    *mdb.User
		Flash string
	}{nil, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	_, err := userStore.SelectFromName(accountName)

	if err == nil {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	uid, eerr := userStore.Insert(accountName, calculatePasshash(accountName, password))
	if eerr != nil {
		fmt.Println(eerr.Error())
		return
	}

	session := getSession(r)
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

var indexCache = template.Must(template.New("layout.html").Funcs(template.FuncMap{
	"imageURL": imageURL,
}).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("index.html"),
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	results := []*Post{}

	rs := postStore.Select50OrderByCreatedAt()
	for _, r := range rs {
		results = append(results, &Post{Post: *r})
	}

	posts, merr := makePosts(results, getCSRFToken(r), false)
	if merr != nil {
		fmt.Println(merr)
		return
	}

	err := indexCache.Execute(w, struct {
		Posts     []*Post
		Me        *mdb.User
		CSRFToken string
		Flash     string
	}{posts, me, getCSRFToken(r), getFlash(w, r, "notice")})

	if err != nil {
		log.Print(err)
	}
}

func getAccountName(c web.C, w http.ResponseWriter, r *http.Request) {
	user, uerr := userStore.SelectFromName(c.URLParams["accountName"])

	if uerr != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []*Post{}
	rs := postStore.SelectOrderByCreatedAtWhereUserId(user.ID)
	for _, r := range rs {
		results = append(results, &Post{Post: *r})
	}

	posts, merr := makePosts(results, getCSRFToken(r), false)
	if merr != nil {
		fmt.Println(merr)
		return
	}

	commentCount := commentStore.SelectCountWhereUserId(user.ID)

	postIDs := []int{}
	for _, r := range rs {
		postIDs = append(postIDs, r.ID)
	}
	postCount := len(postIDs)

	commentedCount := 0
	for _, v := range postIDs {
		commentedCount += commentStore.SelectCountWherePostId(v)
	}

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("user.html"),
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Posts          []*Post
		User           *mdb.User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             *mdb.User
	}{posts, user, postCount, commentCount, commentedCount, me})
}

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(parseErr)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, terr := time.Parse(ISO8601_FORMAT, maxCreatedAt)
	if terr != nil {
		fmt.Println(terr)
		return
	}

	results := []*Post{}
	rs := postStore.SelectOrderByCreatedAtWhereCreatedAt(t)
	for _, r := range rs {
		results = append(results, &Post{Post: *r})
	}

	posts, merr := makePosts(results, getCSRFToken(r), false)
	if merr != nil {
		fmt.Println(merr)
		return
	}

	if len(posts) != postsPerPage {
		log.Print("not enough")
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("posts.html").Funcs(fmap).ParseFiles(
		getTemplPath("posts.html"),
		getTemplPath("post.html"),
	)).Execute(w, posts)
}

func getPostsID(c web.C, w http.ResponseWriter, r *http.Request) {
	pid, err := strconv.Atoi(c.URLParams["id"])
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []*Post{}
	rs := postStore.SelectById(pid)
	for _, r := range rs {
		results = append(results, &Post{Post: *r})
	}

	posts, merr := makePosts(results, getCSRFToken(r), true)
	if merr != nil {
		fmt.Println(merr)
		return
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	fmap := template.FuncMap{
		"imageURL": imageURL,
	}

	template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("post_id.html"),
		getTemplPath("post.html"),
	)).Execute(w, struct {
		Post *Post
		Me   *mdb.User
	}{p, me})
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	file, header, ferr := r.FormFile("file")
	if ferr != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, rerr := ioutil.ReadAll(file)
	if rerr != nil {
		fmt.Println(rerr.Error())
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	pid := postStore.Insert(me.ID, mime, r.FormValue("body"))

	mp := map[string]string{"image/jpeg": "jpg", "image/png": "png", "image/gif": "gif"}
	ext := mp[mime]

	name := fmt.Sprintf("../public/image/%d.%s", pid, ext)
	if err := ioutil.WriteFile(name, filedata, 0644); err != nil {
		log.Print(err)
	}
	filedata = nil

	http.Redirect(w, r, "/posts/"+strconv.Itoa(pid), http.StatusFound)
	return
}

func getImage(c web.C, w http.ResponseWriter, r *http.Request) {
	pidStr := c.URLParams["id"]
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	rs := postStore.SelectById(pid)
	post := &Post{Post: *rs[0]}
	ext := c.URLParams["ext"]

	if ext == "jpg" && post.Mime == "image/jpeg" ||
		ext == "png" && post.Mime == "image/png" ||
		ext == "gif" && post.Mime == "image/gif" {
		imgdata, err := ioutil.ReadFile(fmt.Sprintf("../public/image/%d.%s", pid, ext))
		if err != nil {
			log.Print(err)
			return
		}

		w.Header().Set("Content-Type", post.Mime)
		_, err = w.Write(imgdata)
		if err != nil {
			fmt.Println(err.Error())
		}
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	postID, ierr := strconv.Atoi(r.FormValue("post_id"))
	if ierr != nil {
		fmt.Println("post_idは整数のみです")
		return
	}

	commentStore.Insert(postID, me.ID, r.FormValue("comment"))

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := userStore.SelectNonAdmins()

	template.Must(template.ParseFiles(
		getTemplPath("layout.html"),
		getTemplPath("banned.html")),
	).Execute(w, struct {
		Users     []*mdb.User
		Me        *mdb.User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(StatusUnprocessableEntity)
		return
	}

	r.ParseForm()
	strIds := r.Form["uid[]"]
	ids := []int{}
	for _, s := range strIds {
		val, _ := strconv.Atoi(s)
		ids = append(ids, val)
	}
	userStore.DeleteUsers(ids)

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	initMdbs()

	goji.Get("/initialize", getInitialize)
	goji.Get("/login", getLogin)
	goji.Post("/login", postLogin)
	goji.Get("/register", getRegister)
	goji.Post("/register", postRegister)
	goji.Get("/logout", getLogout)
	goji.Get("/", getIndex)
	goji.Get(regexp.MustCompile(`^/@(?P<accountName>[a-zA-Z]+)$`), getAccountName)
	goji.Get("/posts", getPosts)
	goji.Get("/posts/:id", getPostsID)
	goji.Post("/", postIndex)
	goji.Get("/image/:id.:ext", getImage)
	goji.Post("/comment", postComment)
	goji.Get("/admin/banned", getAdminBanned)
	goji.Post("/admin/banned", postAdminBanned)
	if os.Getenv("LOCAL") == "1" {
		goji.Get("/*", http.FileServer(http.Dir("../public")))
	}
	go func() {
		log.Println(http.ListenAndServe(":6060", nil))
	}()

	goji.Abandon(middleware.Logger)

	goji.Serve()
}
