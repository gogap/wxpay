package wxpay

// type API interface {
// 	URL() string
// }

// type defaultAPI struct {
// 	apiType APIType
// 	url     string
// 	// sandboxURL string
// }

// func NewAPI(apiType APIType, isSandbox bool, serverURL string) API {
// 	var url string
// 	if serverURL != "" {
// 		url = serverURL
// 	} else if isSandbox {
// 		url = WxSandboxUrl
// 	} else {
// 		url = WxUrl
// 	}

// 	switch apiType {
// 	case APITypeUnifiedOrder:
// 		url = url + "pay/" + string(apiType)
// 	case APITypeRefund:
// 		url = url + "secapi/pay/" + string(apiType)
// 	}

// 	return &defaultAPI{
// 		apiType: apiType,
// 		url:     url,
// 	}
// }

// func (p *defaultAPI) URL() string {
// 	// if isSandbox {
// 	// 	return p.sandboxURL
// 	// }

// 	return p.url
// }
