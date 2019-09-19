package wxpay

// 请求类型定义
type APIType string

const (
	APITypeUnifiedOrder APIType = "unifiedorder" // 统一下单
	APITypeCloseorder   APIType = "closeorder"   // 关闭订单
	APITypeRefund       APIType = "refund"       // 申请退款
)

const (
	Fail                       = "FAIL"
	Success                    = "SUCCESS"
	HMACSHA256                 = "HMAC-SHA256"
	MD5                        = "MD5"
	Sign                       = "sign"
	WxUrl                      = "https://api.mch.weixin.qq.com"
	WxSandboxUrl               = "https://api.mch.weixin.qq.com/sandboxnew"
	WxpayUrl                   = "https://api.mch.weixin.qq.com/pay/"
	MicroPayUrl                = "https://api.mch.weixin.qq.com/pay/micropay"
	UnifiedOrderUrl            = "https://api.mch.weixin.qq.com/pay/unifiedorder"
	OrderQueryUrl              = "https://api.mch.weixin.qq.com/pay/orderquery"
	ReverseUrl                 = "https://api.mch.weixin.qq.com/secapi/pay/reverse"
	CloseOrderUrl              = "https://api.mch.weixin.qq.com/pay/closeorder"
	RefundUrl                  = "https://api.mch.weixin.qq.com/secapi/pay/refund"
	RefundQueryUrl             = "https://api.mch.weixin.qq.com/pay/refundquery"
	DownloadBillUrl            = "https://api.mch.weixin.qq.com/pay/downloadbill"
	DownloadFundFlowUrl        = "https://api.mch.weixin.qq.com/pay/downloadfundflow"
	ReportUrl                  = "https://api.mch.weixin.qq.com/payitil/report"
	ShortUrl                   = "https://api.mch.weixin.qq.com/tools/shorturl"
	AuthCodeToOpenidUrl        = "https://api.mch.weixin.qq.com/tools/authcodetoopenid"
	SandboxMicroPayUrl         = "https://api.mch.weixin.qq.com/sandboxnew/pay/micropay"
	SandboxUnifiedOrderUrl     = "https://api.mch.weixin.qq.com/sandboxnew/pay/unifiedorder"
	SandboxOrderQueryUrl       = "https://api.mch.weixin.qq.com/sandboxnew/pay/orderquery"
	SandboxReverseUrl          = "https://api.mch.weixin.qq.com/sandboxnew/secapi/pay/reverse"
	SandboxCloseOrderUrl       = "https://api.mch.weixin.qq.com/sandboxnew/pay/closeorder"
	SandboxRefundUrl           = "https://api.mch.weixin.qq.com/sandboxnew/secapi/pay/refund"
	SandboxRefundQueryUrl      = "https://api.mch.weixin.qq.com/sandboxnew/pay/refundquery"
	SandboxDownloadBillUrl     = "https://api.mch.weixin.qq.com/sandboxnew/pay/downloadbill"
	SandboxDownloadFundFlowUrl = "https://api.mch.weixin.qq.com/sandboxnew/pay/downloadfundflow"
	SandboxReportUrl           = "https://api.mch.weixin.qq.com/sandboxnew/payitil/report"
	SandboxShortUrl            = "https://api.mch.weixin.qq.com/sandboxnew/tools/shorturl"
	SandboxAuthCodeToOpenidUrl = "https://api.mch.weixin.qq.com/sandboxnew/tools/authcodetoopenid"
)
