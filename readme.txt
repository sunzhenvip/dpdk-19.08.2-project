git初始化设置
    1、git init
    2、git config user.email "test@qq.com"
    3、git config user.name "test"
    4、git remote add origin https://github.com/sunzhenvip/指定的xx项目.git(通过vscode或者jetbrains操作也可以)
    5、git add .
    6、git commit -m "x1"
    7、修改当前项目代理地址 git config --local http.proxy 127.0.0.1:10809
    8、使用代理克隆下载 git -c http.proxy="127.0.0.1:10809" clone https://github.com/xx/xx