# team1_BE
| 제1회 스프린트 챌린지 1조 - BackEnd

## <b>Project Structure</b> -- <i>updating!</i>
```
.
├── (.env)
├── README.md
├── cmd
│   └── main.go
├── config
│   ├── authConfig.go
│   └── dbConfig.go
├── controllers
│   └── authController.go
├── go.mod
├── go.sum
├── (google_auth.json)
└── utils
    ├── auth.go
    └── db.go
```
<br>

## How to RUN the Program (with <code>Go</code>)
```
git clone https://github.com/GDG-on-Campus-KHU/team1_BE.git

cd team1_BE

go run cmd/main.go
```
※ Since this <b>BackEnd</b> program is written in <b><code>Go</code></b>, <b>language installation</b> is REQUIRED to run the program.<br>
※ <b><code>.env</code></b> file is <b>required</b> to load the settings and run the program!

## How to RUN the Program (<i>without</i> <code>Go</code>)
To run this program <b>without</b> installation, please execute one of the following binary files<br>
: <b><code>backend-linux</code></b>, <b><code>backend-windows</code></b>, <b><code>backend-macos</code></b>.

※ The <b>binary files</b> above are generated using the following commands:
```
$ GOOS=linux GOARCH=amd64 go build -o backend-linux cmd/main.go
$ GOOS=windows GOARCH=amd64 go build -o backend-windows.exe cmd/main.go
$ GOOS=darwin GOARCH=amd64 go build -o backend-macos cmd/main.go
```