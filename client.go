package wxpay

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/nanjishidu/gomini/gocrypto"
)

const bodyType = "application/xml; charset=utf-8"

type RequestResult struct {
	APIType         APIType
	RequestParams   Params
	RequestContent  []byte
	ResponseParams  Params
	ResponseContent []byte
	Error           error
}

type Cli interface {
	SendRequest(apiType APIType, params Params, resp interface{}, withCert bool) (result *RequestResult)
	SendRefund(req *ReqRefund) (resp *RespRefund, result *RequestResult)
	ValidateSignAndParams(xmlBytes []byte) (params Params, err error)
	Sign(params Params) string
	Account() (account *Account)
	Decrypt(encryptedInfo []byte) (result []byte, err error)
}

// 创建微信支付客户端
func NewCli(account *Account, options *Options) Cli {
	if options == nil {
		options = &Options{}
	}

	cli := NewClient(account)

	if options.ServerURL != "" {
		cli.serverURL = options.ServerURL
	}

	return cli
}

type Options struct {
	ServerURL string
}

type Client struct {
	account              *Account // 支付账号
	signType             string   // 签名类型
	httpConnectTimeoutMs int      // 连接超时时间
	httpReadTimeoutMs    int      // 读取超时时间
	serverURL            string
	httpClientWithCert   *http.Client
}

// 创建微信支付客户端
func NewClient(account *Account) *Client {
	var serverURL string

	if account.isSandbox {
		serverURL = WxSandboxUrl
	} else {
		serverURL = WxUrl
	}

	client := &Client{
		account:              account,
		signType:             MD5,
		httpConnectTimeoutMs: 2000,
		httpReadTimeoutMs:    1000,
		serverURL:            serverURL,
	}

	if account.certData != nil {
		// 将pkcs12证书转成pem
		cert := pkcs12ToPem(account.certData, account.mchID)

		config := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		transport := &http.Transport{
			TLSClientConfig:    config,
			DisableCompression: true,
		}
		client.httpClientWithCert = &http.Client{Transport: transport}
	}

	return client
}

func (c *Client) SendRequest(apiType APIType, params Params, resp interface{}, withCert bool) (result *RequestResult) {

	// api := NewAPI(apiType, c.options.ServerURL)
	// url := api.URL()
	url := c.getReqUrl(apiType)
	result = &RequestResult{
		APIType: apiType,
	}

	//h := &http.Client{}
	result.RequestParams = c.FillRequestData(params)
	result.RequestContent = []byte(MapToXml(result.RequestParams))
	//logrus.Infoln(url, string(result.RequestContent))

	httpCli := http.DefaultClient
	if withCert {
		httpCli = c.httpClientWithCert
	}
	response, err := httpCli.Post(url, bodyType, bytes.NewReader(result.RequestContent))
	if err != nil {
		result.Error = err
		return
	}
	defer response.Body.Close()

	res, err := ioutil.ReadAll(response.Body)
	if err != nil {
		result.Error = err
		return
	}

	result.ResponseContent = res

	result.ResponseParams, err = c.ValidateSignAndParams(res)
	if err != nil {
		result.Error = err
		return
	}

	if resp != nil {
		err = xml.Unmarshal(res, resp)
		if err != nil {
			result.Error = err
			return
		}
	}

	return
}

func (c *Client) SendRefund(req *ReqRefund) (resp *RespRefund, result *RequestResult) {
	resp = new(RespRefund)
	result = c.request(APITypeRefund, req, resp)

	return
}

func (c *Client) request(apiType APIType, req, resp interface{}) (result *RequestResult) {
	result = &RequestResult{
		APIType: apiType,
	}

	el := reflect.ValueOf(req).Elem()
	elType := el.Type()
	elNumField := el.NumField()

	reqParams := Params{}
	for i := 0; i < elNumField; i++ {
		reqParams[elType.Field(i).Tag.Get("json")] = fmt.Sprintf("%v", el.Field(i).Interface())
	}

	result = c.SendRequest(apiType, reqParams, resp, true)

	return
}

func (c *Client) Decrypt(encryptedInfo []byte) (result []byte, err error) {
	encInfo, err := base64.StdEncoding.DecodeString(string(encryptedInfo))
	if err != nil {
		return
	}

	err = gocrypto.SetAesKey(strings.ToLower(gocrypto.Md5(c.account.apiKey)))
	if err != nil {
		return
	}

	result, err = gocrypto.AesECBDecrypt([]byte(encInfo))
	if err != nil {
		return
	}

	return
}

func (c *Client) getReqUrl(apiType APIType) string {
	switch apiType {
	case APITypeRefund:
		return c.serverURL + "/secapi/pay/" + string(apiType)
	default:
		return c.serverURL + "/pay/" + string(apiType)
	}
}

// func (p *Client) ParseResponse(apiType APIType, res []byte) (respParams Params, err error) {
// 	resp, err := c.processResponseXml(string(res))
// 	if err != nil {
// 		return
// 	}

// 	// 根据请求类型，进一步校验返回参数
// 	switch apiType {
// 	case APITypeUnifiedOrder, APITypeRefund:

// 	}

// 	return nil, errors.New("return_code value is invalid in XML")
// }

func (p *Client) Account() (account *Account) {
	return p.account
}

func (c *Client) SetHttpConnectTimeoutMs(ms int) {
	c.httpConnectTimeoutMs = ms
}

func (c *Client) SetHttpReadTimeoutMs(ms int) {
	c.httpReadTimeoutMs = ms
}

func (c *Client) SetSignType(signType string) {
	c.signType = signType
}

func (c *Client) SetAccount(account *Account) {
	c.account = account
}

// 向 params 中添加 appid、mch_id、nonce_str、sign_type、sign
func (c *Client) FillRequestData(params Params) Params {
	params["appid"] = c.account.appID
	params["mch_id"] = c.account.mchID
	params["nonce_str"] = NonceStr()
	params["sign_type"] = c.signType
	params["sign"] = c.Sign(params)
	return params
}

// https no cert post
func (c *Client) postWithoutCert(url string, params Params) (string, error) {
	h := &http.Client{}
	p := c.FillRequestData(params)
	response, err := h.Post(url, bodyType, strings.NewReader(MapToXml(p)))
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	res, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(res), nil
}

// https need cert post
func (c *Client) postWithCert(url string, params Params) (string, error) {
	if c.account.certData == nil {
		return "", errors.New("证书数据为空")
	}

	// 将pkcs12证书转成pem
	cert := pkcs12ToPem(c.account.certData, c.account.mchID)

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	transport := &http.Transport{
		TLSClientConfig:    config,
		DisableCompression: true,
	}
	h := &http.Client{Transport: transport}
	p := c.FillRequestData(params)
	response, err := h.Post(url, bodyType, strings.NewReader(MapToXml(p)))
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	res, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	return string(res), nil
}

// 生成带有签名的xml字符串
func (c *Client) generateSignedXml(params Params) string {
	sign := c.Sign(params)
	params.SetString(Sign, sign)
	return MapToXml(params)
}

// 验证签名
func (c *Client) ValidSign(params Params) bool {
	if !params.ContainsKey(Sign) {
		return false
	}
	return params.GetString(Sign) == c.Sign(params)
}

// 签名
func (c *Client) Sign(params Params) string {
	// 创建切片
	var keys = make([]string, 0, len(params))
	// 遍历签名参数
	for k := range params {
		if k != "sign" { // 排除sign字段
			keys = append(keys, k)
		}
	}

	// 由于切片的元素顺序是不固定，所以这里强制给切片元素加个顺序
	sort.Strings(keys)

	//创建字符缓冲
	var buf bytes.Buffer
	for _, k := range keys {
		if len(params.GetString(k)) > 0 {
			buf.WriteString(k)
			buf.WriteString(`=`)
			buf.WriteString(params.GetString(k))
			buf.WriteString(`&`)
		}
	}
	// 加入apiKey作加密密钥
	buf.WriteString(`key=`)
	buf.WriteString(c.account.apiKey)

	var (
		dataMd5    [16]byte
		dataSha256 []byte
		str        string
	)

	switch c.signType {
	case MD5:
		dataMd5 = md5.Sum(buf.Bytes())
		str = hex.EncodeToString(dataMd5[:]) //需转换成切片
	case HMACSHA256:
		h := hmac.New(sha256.New, []byte(c.account.apiKey))
		h.Write(buf.Bytes())
		dataSha256 = h.Sum(nil)
		str = hex.EncodeToString(dataSha256[:])
	}

	return strings.ToUpper(str)
}

// 校验返回值
func (c *Client) ValidateSignAndParams(xmlBytes []byte) (params Params, err error) {
	respBase := &RespBase{}
	err = xml.Unmarshal(xmlBytes, respBase)
	if err != nil {
		return
	}

	params = XmlToMap(string(xmlBytes))

	returnCode := respBase.ReturnCode

	if returnCode == Fail {
		return
	} else if returnCode == Success {
		if c.ValidSign(params) {
			return params, nil
		} else {
			return nil, errors.New("invalid sign value in XML")
		}
	} else {
		return nil, errors.New("return_code value is invalid in XML")
	}
}

// // 校验返回值
// func (c *Client) ValidateSignAndParams(xmlBytes []byte) (params Params, err error) {
// 	return c.processResponseXml(string(xmlBytes))
// }

// 处理 HTTPS API返回数据，转换成Map对象。return_code为SUCCESS时，验证签名。
func (c *Client) processResponseXml(xmlStr string) (Params, error) {
	var returnCode string
	params := XmlToMap(xmlStr)
	if params.ContainsKey("return_code") {
		returnCode = params.GetString("return_code")
	} else {
		return nil, errors.New("no return_code in XML")
	}
	if returnCode == Fail {
		return params, nil
	} else if returnCode == Success {
		if c.ValidSign(params) {
			return params, nil
		} else {
			return nil, errors.New("invalid sign value in XML")
		}
	} else {
		return nil, errors.New("return_code value is invalid in XML")
	}
}

// 统一下单
func (c *Client) UnifiedOrder(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxUnifiedOrderUrl
	} else {
		url = UnifiedOrderUrl
	}
	xmlStr, err := c.postWithoutCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXml(xmlStr)
}

// 刷卡支付
func (c *Client) MicroPay(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxMicroPayUrl
	} else {
		url = MicroPayUrl
	}
	xmlStr, err := c.postWithoutCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXml(xmlStr)
}

// 退款
func (c *Client) Refund(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxRefundUrl
	} else {
		url = RefundUrl
	}
	xmlStr, err := c.postWithCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXml(xmlStr)
}

// 订单查询
func (c *Client) OrderQuery(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxOrderQueryUrl
	} else {
		url = OrderQueryUrl
	}
	xmlStr, err := c.postWithoutCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXml(xmlStr)
}

// 退款查询
func (c *Client) RefundQuery(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxRefundQueryUrl
	} else {
		url = RefundQueryUrl
	}
	xmlStr, err := c.postWithoutCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXml(xmlStr)
}

// 撤销订单
func (c *Client) Reverse(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxReverseUrl
	} else {
		url = ReverseUrl
	}
	xmlStr, err := c.postWithCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXml(xmlStr)
}

// 关闭订单
func (c *Client) CloseOrder(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxCloseOrderUrl
	} else {
		url = CloseOrderUrl
	}
	xmlStr, err := c.postWithoutCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXml(xmlStr)
}

// 对账单下载
func (c *Client) DownloadBill(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxDownloadBillUrl
	} else {
		url = DownloadBillUrl
	}
	xmlStr, err := c.postWithoutCert(url, params)

	p := make(Params)

	// 如果出现错误，返回XML数据
	if strings.Index(xmlStr, "<") == 0 {
		p = XmlToMap(xmlStr)
		return p, err
	} else { // 正常返回csv数据
		p.SetString("return_code", Success)
		p.SetString("return_msg", "ok")
		p.SetString("data", xmlStr)
		return p, err
	}
}

func (c *Client) DownloadFundFlow(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxDownloadFundFlowUrl
	} else {
		url = DownloadFundFlowUrl
	}
	xmlStr, err := c.postWithCert(url, params)

	p := make(Params)

	// 如果出现错误，返回XML数据
	if strings.Index(xmlStr, "<") == 0 {
		p = XmlToMap(xmlStr)
		return p, err
	} else { // 正常返回csv数据
		p.SetString("return_code", Success)
		p.SetString("return_msg", "ok")
		p.SetString("data", xmlStr)
		return p, err
	}
}

// 交易保障
func (c *Client) Report(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxReportUrl
	} else {
		url = ReportUrl
	}
	xmlStr, err := c.postWithoutCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXml(xmlStr)
}

// 转换短链接
func (c *Client) ShortUrl(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxShortUrl
	} else {
		url = ShortUrl
	}
	xmlStr, err := c.postWithoutCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXml(xmlStr)
}

// 授权码查询OPENID接口
func (c *Client) AuthCodeToOpenid(params Params) (Params, error) {
	var url string
	if c.account.isSandbox {
		url = SandboxAuthCodeToOpenidUrl
	} else {
		url = AuthCodeToOpenidUrl
	}
	xmlStr, err := c.postWithoutCert(url, params)
	if err != nil {
		return nil, err
	}
	return c.processResponseXml(xmlStr)
}
