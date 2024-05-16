package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// ----------------------------------------
// 初回N12_AuthenticationRequestを実行する。
// 受信したEAP-IdentityまたはEAP-AKA' challenge(AT_IDENTITY)の実体Identityから抽出されたIMSIとNetworkNameを引数に取ることを想定している。
// なお、設定ファイルrad5gcgwconf.yamlに記載した「ausfAddress」がここで使われる。
func authReqFirst(imsi, nwName string) (int, string, error) {
	log.Println("[authReqFirst] process start")
	var processFailFlag bool = false
	var authFirstReqErr error
	var n12apiFirstReqUrl string = "http://" + n12AUSFaddress + "/nausf-auth/v1/ue-authentications"
	var authenticationInfo struct {
		SupiOrSuci         string `json:"supiOrSuci"`
		ServingNetworkName string `json:"servingNetworkName"`
	}
	authenticationInfo.SupiOrSuci = imsi
	authenticationInfo.ServingNetworkName = nwName

	// 引数とJSON用構造体からMarshalize実行して、request bodyを生成する。
	marshalizedAuthenticationInfo, marshalizingErr := json.Marshal(authenticationInfo)
	if marshalizingErr != nil {
		authFirstReqErr = marshalizingErr
		processFailFlag = true
		log.Printf("[authReqFirst] JSON marshalizing error / %v\n", marshalizingErr)
	}
	firstReqBodyReader := bytes.NewReader(marshalizedAuthenticationInfo)

	// HTTP Requestを生成する。
	// 生成できたら、初回N12_AuthenticationRequestに必要なヘッダを付与する。
	firstReq, firstRequestGenerateErr := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		n12apiFirstReqUrl,
		firstReqBodyReader)
	if firstRequestGenerateErr != nil {
		authFirstReqErr = firstRequestGenerateErr
		processFailFlag = true
		log.Printf("[authReqFirst] HTTP request generation error / %v\n", firstRequestGenerateErr)
	} else {
		firstReq.Header.Add("content-type", "application/json")
		firstReq.Header.Add("accept", "application/3gppHal+json")
		firstReq.Header.Add("accept", "application/problem+json")
	}

	// ここまでにprocessAbortedフラグが立っていなければ、HTTPクライアントを設定してRequestを送信する。
	var respStCode int
	var respBodyStrings string
	if !processFailFlag {
		client := http.Client{
			Timeout: 5 * time.Second,
		}
		res, sendRequestErr := client.Do(firstReq)
		log.Printf("[authReqFirst] HTTP request send (for %v)\n", authenticationInfo.SupiOrSuci)
		// Request送信して、送信失敗ケースとResponse body読み取り失敗ケースのエラーハンドリングを実施。
		// 正常にResponse受信してbody読み取れたら、bodyは[]byteからstringに変換して戻り値に格納する。
		// ※この関数実施後に、ファクトリ関数authRespBodyDecodeを用いてJSON marshalize＆base64デコードを行うことを想定。
		if sendRequestErr != nil {
			authFirstReqErr = sendRequestErr
			log.Printf("[authReqFirst] fail to send HTTP request / %v\n", sendRequestErr)
		} else {
			resBodyBytes, readingBodyErr := io.ReadAll(res.Body)
			if readingBodyErr != nil {
				authFirstReqErr = readingBodyErr
				log.Printf("[authReqFirst] HTTP response STATUS: %v received.\n", res.Status)
				log.Printf("[authReqFirst] HTTP response body reading error / %v\n", readingBodyErr)
				res.Body.Close()
			} else {
				respStCode = res.StatusCode
				respBodyStrings = string(resBodyBytes)
				log.Printf("[authReqFirst] HTTP response STATUS: %v received.\n", res.Status)
				log.Printf("[authReqFirst] HTTP response body reading complete (for %v)\n", authenticationInfo.SupiOrSuci)
				res.Body.Close()
			}
		}
	}
	return respStCode, respBodyStrings, authFirstReqErr
}

// ----------------------------------------
// 初回以降のAuthenticationRequestで、端末からのEAP-MessageをN12 IFに載せ替えて送出するためのファクトリ関数。
// EAP-IDに紐付いたHTTP Request送出先URIを取得しなければならないため、別ソースのファクトリ関数eapIdTableLoadを使用する。
// なお、引数はEAP-Message（の[]byte）利用が前提のため、EAP-IDについてはRFC3748上、引数の2byte目(つまり[1])を抽出すればよい。
func authReqExchange(eapContents []byte) (int, string, error) {
	log.Println("[authReqExchange] process start")
	var processFailFlag bool = false
	var authReqExchangeErr error
	var eapId uint8 = eapContents[1]
	// 引数のバイトスライスをhex文字列に変換する。
	// N12 HTTP APIはEAP Payloadを「Hex表記の文字列をBase64エンコードしたもの」で格納しなければならないため、大変ややこしい。
	// 「元Payloadバイトスライス(引数)」→「元PayloadバイトスライスをHex表記した文字列」→「Hex表記文字列をBase64エンコード」
	encodedStrFromHex := hex.EncodeToString(eapContents)
	bytesforBase64encoding := []byte(encodedStrFromHex)
	base64encodedEapMsg := make([]byte, base64.StdEncoding.EncodedLen(len(bytesforBase64encoding)))
	base64.StdEncoding.Encode(base64encodedEapMsg, bytesforBase64encoding)
	// このRequestで送出するBodyにはJSONのキーが「eapPayload」しかないため、marshalizeせず直接stringを作る。
	// また、後でRequest bodyに入れ込むため、この段階でReader生成しておく。
	reqExchangeBodyString := `{"eapPayload":"` + string(base64encodedEapMsg) + `"}`
	reqExchangeBodyReader := bytes.NewReader([]byte(reqExchangeBodyString))
	// EAP-IDに紐づくHTTP Request送出先URLを、EAP-ID tableから取得。
	n12apiExchangeUrl, idExistCheck := eapIdTableLoad(eapId)
	if !idExistCheck {
		processFailFlag = true
		log.Println("[authReqExchange] EAP-ID not found in EAP-ID table.")
		authReqExchangeErr = errors.New("eap id not found")
	}

	// これまでの処理で生成したBody用ReaderとRequest送信先URLを用いて、HTTP Requestを生成する。
	// EAP-IDからRequest送信先URLを取得できていなければ、この段階でもエラー発生するはず（なのでこれもログ出力しておく）
	reqExchange, reqExchangeErr := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		n12apiExchangeUrl,
		reqExchangeBodyReader)
	if reqExchangeErr != nil {
		authReqExchangeErr = reqExchangeErr
		processFailFlag = true
		log.Printf("[authReqExchange] HTTP request generation error / %v\n", reqExchangeErr)
	} else {
		reqExchange.Header.Add("content-type", "application/json")
		reqExchange.Header.Add("accept", "application/3gppHal+json")
		reqExchange.Header.Add("accept", "application/problem+json")
	}
	// ここまでにprocessFailFlagが立っていなければ、HTTPクライアントを設定してRequestを送信する。
	var respStCode int
	var respBodyStrings string
	if !processFailFlag {
		client := http.Client{
			Timeout: 5 * time.Second,
		}
		res, sendRequestErr := client.Do(reqExchange)
		log.Printf("[authReqExchange] HTTP request send (for EAP-ID 0x%X from STA)\n", eapId)
		// Request送信して、送信失敗ケースとResponse body読み取り失敗ケースのエラーハンドリングを実施。
		// 正常にResponse受信してbody読み取れたら、bodyは[]byteからstringに変換して戻り値に格納する。
		// ※この関数実施後に、ファクトリ関数authRespBodyDecodeを用いてJSON marshalize＆base64デコードを行うことを想定。
		if sendRequestErr != nil {
			authReqExchangeErr = sendRequestErr
			log.Printf("[authReqExchange] fail to send HTTP request / %v\n", sendRequestErr)
		} else {
			resBodyBytes, readingBodyErr := io.ReadAll(res.Body)
			if readingBodyErr != nil {
				authReqExchangeErr = readingBodyErr
				log.Printf("[authReqExchange] HTTP response STATUS: %v received.\n", res.Status)
				log.Printf("[authReqExchange] HTTP response body reading error / %v\n", readingBodyErr)
				res.Body.Close()
			} else {
				respStCode = res.StatusCode
				respBodyStrings = string(resBodyBytes)
				log.Printf("[authReqExchange] HTTP response STATUS: %v received.\n", res.Status)
				log.Printf("[authReqExchange] HTTP response body reading complete (for EAP-ID 0x%X from STA)\n", eapId)
				res.Body.Close()
			}
		}
	}
	return respStCode, respBodyStrings, authReqExchangeErr
}

// ----------------------------------------
// 上記2つのファクトリ関数で得たResponse body(string)から、Radiusで返すEAP-Message等を抽出するファクトリ関数。
// 引数に「ステータスコード(stCode int)」と「ボディ文字列(respBodyStr string:JSON想定)」を取る。
// （ステータスコードによりJSONフォーマットが変わるため）
// 戻り値は「EAPpayload([]byte)」と「EAP-ID(uint8)」と「str(_linkかcause)」と「エラー」となっている。
// これは関数実行後に、戻り値のEAP-IDとlinkを用いてEAP-ID tableに利用中ID＆Linkを書き込む流れになることを想定している。
func authRespBodyDecode(stCode int, respBodyStr string) ([]byte, uint8, string, error) {
	var eapPayload []byte
	var eapId uint8
	var resultStr string
	var authRespDecodeErr error
	switch stCode {
	case 200:
		// authReqExchangeに対するResponse bodyをデコードする想定。
		// EAP-Success/EAP-Failure/EAPセッション継続の3パターンが存在し、それぞれJSONフォーマットが異なる。
		log.Printf("[Rad-5GC GW] Status Code %v : decoding response body...\n", stCode)
		switch {
		case strings.Contains(respBodyStr, "kSeaf"):
			type eapSuccessJson struct {
				EapPayload string `json:"eapPayload"`
				KSeaf      string `json:"kSeaf"`
			}
			decodedArg := eapSuccessJson{}
			decoder := json.NewDecoder(strings.NewReader(respBodyStr))
			jsonDecodeErr := decoder.Decode(&decodedArg)
			if jsonDecodeErr != nil {
				authRespDecodeErr = jsonDecodeErr
				log.Printf("[Rad-5GC GW] Status Code %v : response body JSON decoding error / %v\n", stCode, jsonDecodeErr)
				log.Printf("[Rad-5GC GW] Status Code %v : response body(error) : %v\n", stCode, respBodyStr)
			} else {
				bhDecodedData, pickedEapId, bhDecodingErr := base64AndHexDecode(stCode, decodedArg.EapPayload)
				if bhDecodingErr != nil {
					authRespDecodeErr = bhDecodingErr
				} else {
					eapPayload = bhDecodedData
					eapId = pickedEapId
					resultStr = decodedArg.KSeaf
					log.Printf("[Rad-5GC GW] Status Code %v (EAP-Success) : decode success.\n", stCode)
				}
			}
		case strings.Contains(respBodyStr, "authResult"):
			type eapFailureJson struct {
				EapPayload string `json:"eapPayload"`
				AuthResult string `json:"authResult"`
			}
			decodedArg := eapFailureJson{}
			decoder := json.NewDecoder(strings.NewReader(respBodyStr))
			jsonDecodeErr := decoder.Decode(&decodedArg)
			if jsonDecodeErr != nil {
				authRespDecodeErr = jsonDecodeErr
				log.Printf("[Rad-5GC GW] Status Code %v : response body JSON decoding error / %v\n", stCode, jsonDecodeErr)
				log.Printf("[Rad-5GC GW] Status Code %v : response body(error) : %v\n", stCode, respBodyStr)
			} else {
				bhDecodedData, pickedEapId, bhDecodingErr := base64AndHexDecode(stCode, decodedArg.EapPayload)
				if bhDecodingErr != nil {
					authRespDecodeErr = bhDecodingErr
				} else {
					eapPayload = bhDecodedData
					eapId = pickedEapId
					resultStr = decodedArg.AuthResult
					log.Printf("[Rad-5GC GW] Status Code %v (EAP-Failure) : decode success.\n", stCode)
				}
			}
		case strings.Contains(respBodyStr, "_links"):
			type n12EapExchange struct {
				EapPayload string `json:"eapPayload"`
				Links      struct {
					Href string `json:"href"`
				} `json:"_links"`
			}
			decodedArg := n12EapExchange{}
			decoder := json.NewDecoder(strings.NewReader(respBodyStr))
			jsonDecodeErr := decoder.Decode(&decodedArg)
			if jsonDecodeErr != nil {
				authRespDecodeErr = jsonDecodeErr
				log.Printf("[Rad-5GC GW] Status Code %v : response body JSON decoding error / %v\n", stCode, jsonDecodeErr)
				log.Printf("[Rad-5GC GW] Status Code %v : response body(error) : %v\n", stCode, respBodyStr)
			} else {
				bhDecodedData, pickedEapId, bhDecodingErr := base64AndHexDecode(stCode, decodedArg.EapPayload)
				if bhDecodingErr != nil {
					authRespDecodeErr = bhDecodingErr
				} else {
					eapPayload = bhDecodedData
					eapId = pickedEapId
					resultStr = decodedArg.Links.Href
					log.Printf("[Rad-5GC GW] Status Code %v (EAP session ongoing) : decode success.\n", stCode)
				}
			}
		default:
			log.Printf("[Rad-5GC GW] Status Code %v : unknown response body", stCode)
			authRespDecodeErr = errors.New("unknown response body")
		}
	case 201:
		// authReqFirstに対するResponse bodyをデコードする想定。
		log.Printf("[Rad-5GC GW] Status Code %v : decoding response body...\n", stCode)
		type authRespFirst struct {
			AuthType      string `json:"authType"`
			FiveGAuthData string `json:"5gAuthData"`
			Links         struct {
				EapSession struct {
					Href string `json:"href"`
				} `json:"eap-session"`
			} `json:"_links"`
			ServingNetworkName string `json:"servingNetworkName"`
		}
		// 引数respBodyStrをJSONから構造体authRespFirstへデコード。
		// 次に、構造体authRespFirstの要素FiveGAuthDataを[]byteに型変換し、base64デコードする。これで戻り値eapPayloadが完成。
		// eapPayloadの2byte目がeapIdとなるのでそのまま抽出し、構造体authRespFirstの要素HrefからURLを抽出。
		decodedArg := authRespFirst{}
		decoder := json.NewDecoder(strings.NewReader(respBodyStr))
		jsonDecodeErr := decoder.Decode(&decodedArg)
		if jsonDecodeErr != nil {
			authRespDecodeErr = jsonDecodeErr
			log.Printf("[Rad-5GC GW] Status Code %v : response body JSON decoding error / %v\n", stCode, jsonDecodeErr)
			log.Printf("[Rad-5GC GW] Status Code %v : response body(error) : %v\n", stCode, respBodyStr)
		} else {
			sixFourDecodedFiveGAuthData := make([]byte, base64.StdEncoding.DecodedLen(len(decodedArg.FiveGAuthData)))
			_, sixFourDecodeErr := base64.StdEncoding.Decode(sixFourDecodedFiveGAuthData, []byte(decodedArg.FiveGAuthData))
			if sixFourDecodeErr != nil {
				authRespDecodeErr = sixFourDecodeErr
				log.Printf("[Rad-5GC GW] Status Code %v : 5gAuthData base64 decoding error / %v\n", stCode, sixFourDecodeErr)
				log.Printf("[Rad-5GC GW] Status Code %v : 5gAuthData(error) : %v\n", stCode, decodedArg.FiveGAuthData)
			} else {
				eapPayload = sixFourDecodedFiveGAuthData
				eapId = sixFourDecodedFiveGAuthData[1]
				resultStr = decodedArg.Links.EapSession.Href
				log.Printf("[Rad-5GC GW] Status Code %v : decode success.\n", stCode)
			}
		}
	default:
		// ステータスコード：400/403/404/500/501がここに該当する想定。
		// JSON構造が現時点では分からないため、一旦は引数respBodyStrをそのまま返す。
		// 恐らくDataType:ProblemDetailと思われるので、将来的には要素causeを抽出してresultStrに返したい。
		log.Printf("[Rad-5GC GW] Status Code %v : decoding response body...\n", stCode)
		resultStr = respBodyStr
		log.Printf("[Rad-5GC GW] Status Code %v / response body : %v\n", stCode, resultStr)
	}
	return eapPayload, eapId, resultStr, authRespDecodeErr
}

// ファクトリ関数authRespBodyDecodeで必要な処理のうち、base64デコード＋Hex文字列byte化の部分を切り出して関数化した。
// 引数はint(ステータスコード)とstring(JSONデコード後のdecodedArg.5gAuthDataまたはdecodedArg.EapPayloadを想定)とする。
// 引数でステータスコードを取るのは、ログ出力に作業対象responseのステータスコードを明記したいため。
// 戻り値は、Hex文字列をbyte化した[]byte型・eapIdを想定したbyte型・エラー型とする。
func base64AndHexDecode(stCode int, str string) ([]byte, uint8, error) {
	var payloadBytes []byte
	var eapId uint8
	var decodeErr error
	sixFourDecodedbytes := make([]byte, base64.StdEncoding.DecodedLen(len(str)))
	_, sixFourDecodeErr := base64.StdEncoding.Decode(sixFourDecodedbytes, []byte(str))
	if sixFourDecodeErr != nil {
		decodeErr = sixFourDecodeErr
		log.Printf("[Rad-5GC GW] Status Code %v : base64 decoding error / %v\n", stCode, sixFourDecodeErr)
	} else {
		hexDecodedBytes := make([]byte, hex.DecodedLen(len(sixFourDecodedbytes)))
		_, hexToByteErr := hex.Decode(hexDecodedBytes, sixFourDecodedbytes)
		if hexToByteErr != nil {
			decodeErr = hexToByteErr
			log.Printf("[Rad-5GC GW] Status Code %v : base64-decoded data cannot change from hex string to byte slice / %v\n", stCode, hexToByteErr)
		} else {
			payloadBytes = hexDecodedBytes
			eapId = hexDecodedBytes[1]
		}
	}
	return payloadBytes, eapId, decodeErr
}
