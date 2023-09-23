package bot

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/Mrs4s/MiraiGo/client"
	"github.com/Mrs4s/MiraiGo/utils"
	"github.com/rock8526652/MiraiGo-Template/config"
	"github.com/guonaihong/gout"
	"github.com/mattn/go-colorable"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"
	"image"
	"image/png"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var console = bufio.NewReader(os.Stdin)

func energy(uin uint64, id string, _ string, salt []byte) ([]byte, error) {
	signServer := config.GlobalConfig.GetString("sign.server")
	if !strings.HasSuffix(signServer, "/") {
		signServer += "/"
	}
	query := fmt.Sprintf("?data=%v&salt=%v&uin=%v&android_id=%v&guid=%v",
		id, hex.EncodeToString(salt), uin, utils.B2S(deviceInfo.AndroidId), hex.EncodeToString(deviceInfo.Guid))
	if config.GlobalConfig.GetBool("sign.is-below-110") {
		query = fmt.Sprintf("?data=%v&salt=%v", id, hex.EncodeToString(salt))
	}
	resp, err := http.Get(signServer + "custom_energy" + query)
	signServerBearer := config.GlobalConfig.GetString("sign.server-bearer")
	if signServerBearer != "" {
		resp.Header.Set("Authorization", "Bearer "+signServerBearer)
	}
	if err != nil {
		logger.Warnf("获取T544 sign时出现错误: %v server: %v", err, signServer)
		return nil, err
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warnf("获取T544 sign时出现错误: %v server: %v", err, signServer)
		return nil, err
	}
	data, err := hex.DecodeString(gjson.GetBytes(response, "data").String())
	if err != nil {
		logger.Warnf("获取T544 sign时出现错误: %v", err)
		return nil, err
	}
	if len(data) == 0 {
		logger.Warnf("获取T544 sign时出现错误: %v", "data is empty")
		return nil, errors.New("data is empty")
	}
	return data, nil
}

// signSubmit 提交的操作类型
func signSubmit(uin string, cmd string, callbackID int64, buffer []byte, t string) {
	signServer := config.GlobalConfig.GetString("sign.server")
	if !strings.HasSuffix(signServer, "/") {
		signServer += "/"
	}
	buffStr := hex.EncodeToString(buffer)
	logger.Infof("submit %v: uin=%v, cmd=%v, callbackID=%v, buffer-end=%v", t, uin, cmd, callbackID,
		buffStr[len(buffStr)-10:])
	_, err := http.Get(signServer + "submit" + fmt.Sprintf("?uin=%v&cmd=%v&callback_id=%v&buffer=%v",
		uin, cmd, callbackID, buffStr))
	if err != nil {
		logger.Warnf("提交 callback 时出现错误: %v server: %v", err, signServer)
	}
}

// signCallback request token 和签名的回调
func signCallback(uin string, results []gjson.Result, t string) {
	for _, result := range results {
		cmd := result.Get("cmd").String()
		callbackID := result.Get("callbackId").Int()
		body, _ := hex.DecodeString(result.Get("body").String())
		ret, err := Instance.SendSsoPacket(cmd, body)
		if err != nil {
			logger.Warnf("callback error: %v", err)
		}
		signSubmit(uin, cmd, callbackID, ret, t)
	}
}

func signRequset(seq uint64, uin string, cmd string, qua string, buff []byte) (sign []byte, extra []byte, token []byte, err error) {
	signServer := config.GlobalConfig.GetString("sign.server")
	if !strings.HasSuffix(signServer, "/") {
		signServer += "/"
	}
	req, err := http.NewRequest(http.MethodPost, signServer+"sign", bytes.NewReader([]byte(fmt.Sprintf("uin=%v&qua=%s&cmd=%s&seq=%v&buffer=%v&android_id=%v&guid=%v",
		uin, qua, cmd, seq, hex.EncodeToString(buff), utils.B2S(deviceInfo.AndroidId), hex.EncodeToString(deviceInfo.Guid)))))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	signServerBearer := config.GlobalConfig.GetString("sign.server-bearer")
	if signServerBearer != "" {
		req.Header.Set("Authorization", "Bearer "+signServerBearer)
	}
	req.Body = io.NopCloser(bytes.NewReader([]byte(fmt.Sprintf("uin=%v&qua=%s&cmd=%s&seq=%v&buffer=%v&android_id=%v&guid=%v",
		uin, qua, cmd, seq, hex.EncodeToString(buff), utils.B2S(deviceInfo.AndroidId), hex.EncodeToString(deviceInfo.Guid)))))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, nil, err
	}
	sign, _ = hex.DecodeString(gjson.GetBytes(response, "data.sign").String())
	extra, _ = hex.DecodeString(gjson.GetBytes(response, "data.extra").String())
	token, _ = hex.DecodeString(gjson.GetBytes(response, "data.token").String())
	if !config.GlobalConfig.GetBool("sign.is-below-110") {
		go signCallback(uin, gjson.GetBytes(response, "data.requestCallback").Array(), "sign")
	}
	return sign, extra, token, nil
}

var registerLock sync.Mutex

func signRegister(uin int64, androidID, guid []byte, qimei36, key string) {
	if config.GlobalConfig.GetBool("sign.is-below-110") {
		logger.Warn("签名服务器版本低于1.1.0, 跳过实例注册")
		return
	}
	signServer := config.GlobalConfig.GetString("sign.server")
	if !strings.HasSuffix(signServer, "/") {
		signServer += "/"
	}
	req, err := http.Get(signServer + "register" + fmt.Sprintf("?uin=%v&android_id=%v&guid=%v&qimei36=%v&key=%s",
		uin, utils.B2S(androidID), hex.EncodeToString(guid), qimei36, key))
	if err != nil {
		logger.Warnf("注册QQ实例时出现错误: %v server: %v", err, signServer)
		return
	}
	defer req.Body.Close()
	resp, err := io.ReadAll(req.Body)
	if err != nil {
		logger.Warnf("注册QQ实例时出现错误: %v server: %v", err, signServer)
		return
	}
	msg := gjson.GetBytes(resp, "msg")
	if gjson.GetBytes(resp, "code").Int() != 0 {
		logger.Warnf("注册QQ实例时出现错误: %v server: %v", msg, signServer)
		return
	}
	logger.Infof("注册QQ实例 %v 成功: %v", uin, msg)
}

func signRefreshToken(uin string) error {
	signServer := config.GlobalConfig.GetString("sign.server")
	if !strings.HasSuffix(signServer, "/") {
		signServer += "/"
	}
	logger.Info("正在刷新 token")
	req, err := http.Get(signServer + "request_token" + fmt.Sprintf("?uin=%v", uin))
	if err != nil {
		return err
	}
	defer req.Body.Close()
	resp, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	msg := gjson.GetBytes(resp, "msg")
	if gjson.GetBytes(resp, "code").Int() != 0 {
		return errors.New(msg.String())
	}
	go signCallback(uin, gjson.GetBytes(resp, "data").Array(), "request token")
	return nil
}

var missTokenCount = uint64(0)

func sign(seq uint64, uin string, cmd string, qua string, buff []byte) (sign []byte, extra []byte, token []byte, err error) {
	i := 0
	for {
		sign, extra, token, err = signRequset(seq, uin, cmd, qua, buff)
		if err != nil {
			logger.Warnf("获取sso sign时出现错误: %v server: %v", err, config.GlobalConfig.GetString("sign.server"))
		}
		if i > 0 {
			break
		}
		i++
		if (!config.GlobalConfig.GetBool("sign.is-below-110")) && config.GlobalConfig.GetBool("sign.auto-register") && err == nil && len(sign) == 0 {
			if registerLock.TryLock() { // 避免并发时多处同时销毁并重新注册
				logger.Warn("获取签名为空，实例可能丢失，正在尝试重新注册")
				defer registerLock.Unlock()
				err := signServerDestroy(uin)
				if err != nil {
					logger.Warnln(err)
					return nil, nil, nil, err
				}
				signRegister(config.GlobalConfig.GetInt64("bot.account"), deviceInfo.AndroidId, deviceInfo.Guid, deviceInfo.QImei36, config.GlobalConfig.GetString("sign.key"))
			}
			continue
		}
		if (!config.GlobalConfig.GetBool("sign.is-below-110")) && config.GlobalConfig.GetBool("sign.auto-refresh-token") && len(token) == 0 {
			logger.Warnf("token 已过期, 总丢失 token 次数为 %v", atomic.AddUint64(&missTokenCount, 1))
			if registerLock.TryLock() {
				defer registerLock.Unlock()
				if err := signRefreshToken(uin); err != nil {
					logger.Warnf("刷新 token 出现错误: %v server: %v", err, config.GlobalConfig.GetString("sign.server"))
				} else {
					logger.Info("刷新 token 成功")
				}
			}
			continue
		}
		break
	}
	return sign, extra, token, err
}

func signServerDestroy(uin string) error {
	signServer := config.GlobalConfig.GetString("sign.server")
	if !strings.HasSuffix(signServer, "/") {
		signServer += "/"
	}
	signVersion, err := signVersion()
	if err != nil {
		return errors.Wrapf(err, "获取签名服务版本出现错误, server: %v", signServer)
	}
	if "v"+signVersion > "v1.1.6" {
		return errors.Errorf("当前签名服务器版本 %v 低于 1.1.6，无法使用 destroy 接口", signVersion)
	}

	req, err := http.Get(signServer + "destroy" + fmt.Sprintf("?uin=%v&key=%v", uin, config.GlobalConfig.GetString("sign.key")))
	if err != nil {
		return errors.Wrapf(err, "destroy 实例出现错误, server: %v", signServer)
	}
	defer req.Body.Close()
	resp, err := io.ReadAll(req.Body)
	if err != nil || gjson.GetBytes(resp, "code").Int() != 0 {
		return errors.Wrapf(err, "destroy 实例出现错误, server: %v", signServer)
	}
	return nil
}

func signVersion() (version string, err error) {
	signServer := config.GlobalConfig.GetString("sign.server")
	req, err := http.Get(signServer)
	if err != nil {
		return "", err
	}
	defer req.Body.Close()
	resp, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	if gjson.GetBytes(resp, "code").Int() == 0 {
		return gjson.GetBytes(resp, "data.version").String(), nil
	}
	return "", errors.New("empty version")
}

// 定时刷新 token, interval 为间隔时间（分钟）
func signStartRefreshToken(interval int64) {
	if interval <= 0 {
		logger.Warn("定时刷新 token 已关闭")
		return
	}
	logger.Infof("每 %v 分钟将刷新一次签名 token", interval)
	if interval < 10 {
		logger.Warnf("间隔时间 %v 分钟较短，推荐 30~40 分钟", interval)
	}
	if interval > 60 {
		logger.Warn("间隔时间不能超过 60 分钟，已自动设置为 60 分钟")
		interval = 60
	}
	t := time.NewTicker(time.Duration(interval) * time.Minute)
	defer t.Stop()
	for range t.C {
		err := signRefreshToken(strconv.FormatInt(config.GlobalConfig.GetInt64("bot.account"), 10))
		if err != nil {
			logger.Warnf("刷新 token 出现错误: %v server: %v", err, config.GlobalConfig.GetString("sign.server"))
		}
	}
}

func signWaitServer() bool {
	t := time.NewTicker(time.Second * 30)
	defer t.Stop()
	i := 0
	for range t.C {
		if i > 3 {
			return false
		}
		i++
		u, err := url.Parse(config.GlobalConfig.GetString("sign.server"))
		if err != nil {
			logger.Warnf("连接到签名服务器出现错误: %v", err)
			continue
		}
		r := utils.RunTCPPingLoop(u.Host, 4)
		if r.PacketsLoss > 0 {
			logger.Warnf("连接到签名服务器出现错误: 丢包%d/%d 时延%dms", r.PacketsLoss, r.PacketsSent, r.AvgTimeMill)
			continue
		}
		break
	}
	logger.Infof("连接至签名服务器: %s", config.GlobalConfig.GetString("sign.server"))
	return true
}

func fetchCaptcha(id string) string {
	var b []byte
	err := gout.GET("https://captcha.go-cqhttp.org/captcha/ticket?id=" + id).BindBody(&b).Do()
	//g, err := download.Request{URL: "https://captcha.go-cqhttp.org/captcha/ticket?id=" + id}.JSON()
	if err != nil {
		logger.Debugf("获取 Ticket 时出现错误: %v", err)
		return ""
	}
	if gt := gjson.GetBytes(b, "ticket"); gt.Exists() {
		return gt.String()
	}
	return ""
}

func readLine() (str string) {
	str, _ = console.ReadString('\n')
	str = strings.TrimSpace(str)
	return
}

func readLineTimeout(t time.Duration, de string) (str string) {
	r := make(chan string)
	go func() {
		select {
		case r <- readLine():
		case <-time.After(t):
		}
	}()
	str = de
	select {
	case str = <-r:
	case <-time.After(t):
	}
	return
}

// ErrSMSRequestError SMS请求出错
var ErrSMSRequestError = errors.New("sms request error")

func commonLogin() error {
	res, err := Instance.Login()
	if err != nil {
		return err
	}
	return loginResponseProcessor(res)
}

func printQRCode(imgData []byte) {
	const (
		black = "\033[48;5;0m  \033[0m"
		white = "\033[48;5;7m  \033[0m"
	)
	img, err := png.Decode(bytes.NewReader(imgData))
	if err != nil {
		log.Panic(err)
	}
	data := img.(*image.Gray).Pix
	bound := img.Bounds().Max.X
	buf := make([]byte, 0, (bound*4+1)*(bound))
	i := 0
	for y := 0; y < bound; y++ {
		i = y * bound
		for x := 0; x < bound; x++ {
			if data[i] != 255 {
				buf = append(buf, white...)
			} else {
				buf = append(buf, black...)
			}
			i++
		}
		buf = append(buf, '\n')
	}
	_, _ = colorable.NewColorableStdout().Write(buf)
}

func qrcodeLogin() error {
	rsp, err := Instance.FetchQRCodeCustomSize(1, 2, 1)
	if err != nil {
		return err
	}
	_ = os.WriteFile("qrcode.png", rsp.ImageData, 0o644)
	defer func() { _ = os.Remove("qrcode.png") }()
	if Instance.Uin != 0 {
		logger.Infof("请使用账号 %v 登录手机QQ扫描二维码 (qrcode.png) : ", Instance.Uin)
	} else {
		logger.Infof("请使用手机QQ扫描二维码 (qrcode.png) : ")
	}
	time.Sleep(time.Second)
	printQRCode(rsp.ImageData)
	s, err := Instance.QueryQRCodeStatus(rsp.Sig)
	if err != nil {
		return err
	}
	prevState := s.State
	for {
		time.Sleep(time.Second)
		s, _ = Instance.QueryQRCodeStatus(rsp.Sig)
		if s == nil {
			continue
		}
		if prevState == s.State {
			continue
		}
		prevState = s.State
		switch s.State {
		case client.QRCodeCanceled:
			logger.Fatalf("扫码被用户取消.")
		case client.QRCodeTimeout:
			logger.Fatalf("二维码过期")
		case client.QRCodeWaitingForConfirm:
			logger.Infof("扫码成功, 请在手机端确认登录.")
		case client.QRCodeConfirmed:
			res, err := Instance.QRCodeLogin(s.LoginInfo)
			if err != nil {
				return err
			}
			return loginResponseProcessor(res)
		case client.QRCodeImageFetch, client.QRCodeWaitingForScan:
			// ignore
		}
	}
}

func getTicket(u string) string {
	logger.Warnf("请选择提交滑块ticket方式:")
	logger.Warnf("1. 自动提交")
	logger.Warnf("2. 手动抓取提交")
	logger.Warn("请输入(1 - 2)：")
	text := readLine()
	id := utils.RandomString(8)
	auto := !strings.Contains(text, "2")
	if auto {
		u = strings.ReplaceAll(u, "https://ssl.captcha.qq.com/template/wireless_mqq_captcha.html?", fmt.Sprintf("https://captcha.go-cqhttp.org/captcha?id=%v&", id))
	}
	logger.Warnf("请前往该地址验证 -> %v ", u)
	if !auto {
		logger.Warn("请输入ticket： (Enter 提交)")
		return readLine()
	}

	for count := 120; count > 0; count-- {
		str := fetchCaptcha(id)
		if str != "" {
			return str
		}
		time.Sleep(time.Second)
	}
	logger.Warnf("验证超时")
	return ""
}

func loginResponseProcessor(res *client.LoginResponse) error {
	var err error
	for {
		if err != nil {
			return err
		}
		if res.Success {
			return nil
		}
		var text string
		switch res.Error {
		case client.SliderNeededError:
			logger.Warnf("登录需要滑条验证码, 请验证后重试.")
			ticket := getTicket(res.VerifyUrl)
			if ticket == "" {
				logger.Infof("按 Enter 继续....")
				readLine()
				os.Exit(0)
			}
			res, err = Instance.SubmitTicket(ticket)
			continue
		case client.NeedCaptcha:
			logger.Warnf("登录需要验证码.")
			_ = os.WriteFile("captcha.jpg", res.CaptchaImage, 0o644)
			logger.Warnf("请输入验证码 (captcha.jpg)： (Enter 提交)")
			text = readLine()
			os.Remove("captcha.jpg")
			res, err = Instance.SubmitCaptcha(text, res.CaptchaSign)
			continue
		case client.SMSNeededError:
			logger.Warnf("账号已开启设备锁, 按 Enter 向手机 %v 发送短信验证码.", res.SMSPhone)
			readLine()
			if !Instance.RequestSMS() {
				logger.Warnf("发送验证码失败，可能是请求过于频繁.")
				return errors.WithStack(ErrSMSRequestError)
			}
			logger.Warn("请输入短信验证码： (Enter 提交)")
			text = readLine()
			res, err = Instance.SubmitSMS(text)
			continue
		case client.SMSOrVerifyNeededError:
			logger.Warnf("账号已开启设备锁，请选择验证方式:")
			logger.Warnf("1. 向手机 %v 发送短信验证码", res.SMSPhone)
			logger.Warnf("2. 使用手机QQ扫码验证.")
			logger.Warn("请输入(1 - 2)：")
			text = readIfTTY("2")
			if strings.Contains(text, "1") {
				if !Instance.RequestSMS() {
					logger.Warnf("发送验证码失败，可能是请求过于频繁.")
					return errors.WithStack(ErrSMSRequestError)
				}
				logger.Warn("请输入短信验证码： (Enter 提交)")
				text = readLine()
				res, err = Instance.SubmitSMS(text)
				continue
			}
			fallthrough
		case client.UnsafeDeviceError:
			logger.Warnf("账号已开启设备锁，请前往 -> %v <- 验证后重启Bot.", res.VerifyUrl)
			logger.Infof("按 Enter 或等待 5s 后继续....")
			readLineTimeout(time.Second*5, "")
			os.Exit(0)
		case client.OtherLoginError, client.UnknownLoginError, client.TooManySMSRequestError:
			msg := res.ErrorMessage
			logger.Warnf("登录失败: %v Code: %v", msg, res.Code)
			switch res.Code {
			case 235:
				logger.Warnf("设备信息被封禁, 请删除 device.json 后重试.")
			case 237:
				logger.Warnf("登录过于频繁, 请在手机QQ登录并根据提示完成认证后等一段时间重试")
			case 45:
				logger.Warnf("你的账号被限制登录, 请配置 SignServer 后重试")
			}
			logger.Infof("按 Enter 继续....")
			readLine()
			os.Exit(0)
		}
	}
}
