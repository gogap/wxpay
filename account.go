package wxpay

import (
	"io/ioutil"
	"log"
)

type Account struct {
	appID     string
	mchID     string
	apiKey    string
	certData  []byte
	isSandbox bool
}

// 创建微信支付账号
func NewAccount(appID string, mchID string, apiKey string, isSanbox bool) *Account {
	return &Account{
		appID:     appID,
		mchID:     mchID,
		apiKey:    apiKey,
		isSandbox: isSanbox,
	}
}

func (a *Account) AppID() (appID string) {
	return a.appID
}

func (a *Account) MchID() (mchID string) {
	return a.mchID
}

func (a *Account) ApiKey() (apiKey string) {
	return a.apiKey
}

func (a *Account) SetCertData(certData []byte) {
	a.certData = certData
}

// 设置证书
func (a *Account) LoadCertDataFromFile(certPath string) {
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		log.Println("读取证书失败")
		return
	}
	a.certData = certData
}
