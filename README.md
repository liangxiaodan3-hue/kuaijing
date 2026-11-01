# 快鲸 Web 使用说明

## 功能
漫画 / 视频 / 社区 / 小说 / 观看历史。漫画、视频、小说、社区内容来自原站，漫画与小说 VIP 自动解锁。

## 直接用（推荐 · 不用同 WiFi）
手机浏览器打开：

**https://liangxiaodan3-hue.github.io/kuaijing/**

- iPhone Safari → 分享 → 添加到主屏幕
- Android Chrome → 菜单 → 添加到主屏幕

流量、任何 WiFi 都能开，跟 app 一样。

## 本地打开（备用）
把 `web-app/` 里的 `index.html` 双击用浏览器打开即可。
（`file://` 协议下 Service Worker 不可用，但功能正常。）

## 本地服务器（开发调试）
```
cd web-app
python -m http.server 8080
```
手机连同一 WiFi 访问 `http://电脑IP:8080`。
