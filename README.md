# team1_BE
- *Google Developer Groups on Campus KHU*
- *The 1st Sprint Challenge (Part Joint Project)*
- Keyword: **`Disaster`**
<br>

## `JAETI`: Disaster News Summary Service
<img src="https://drive.google.com/uc?id=1GN_KJw12iLKW_QegPsj8LC2Nb9E4EOuH" width=35%>

### Key Features
- **Concise Delivery** of Disaster Information
- **Filter** news articles using **20+ keywords**
- Provide **summarized text** with original article URLs → Direct connection to **full articles**
- Simple Google Login → **Save** news articles → View saved articles on **MyPage**

### Tech Stack
- **FrontEnd**: **`React`** + **`Vite`**, **`Redux`** (state management)
- **BackEnd**: Server written in **`Go`**
- **Database**: **`SQLite`** for lightweight and efficient data storage
- **AI Integration**: **`Chat GPT API`** for keyword filtering & **text summarization**

<br>

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
