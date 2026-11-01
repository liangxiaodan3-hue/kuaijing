# 快鲸 Web 使用说明

## 直接打开（最快）
把 `web-app/` 文件夹里的 `index.html` 双击用浏览器打开即可。

> 注意：浏览器直接打开 `file://` 协议时，Service Worker 不可用，但功能正常。

## 手机上用（推荐）
1. 电脑上在 web-app 文件夹开一个本地服务器：
   ```
   cd web-app
   python -m http.server 8080
   ```
2. 手机和电脑连同一个 WiFi，手机浏览器访问 `http://电脑IP:8080`
3. iPhone Safari → 分享 → 添加到主屏幕
4. Android Chrome → 菜单 → 添加到主屏幕

## 添加到主屏幕后
独立窗口运行，无浏览器地址栏，跟原生 app 一样。
