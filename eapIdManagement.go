package main

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
)

// EAP idとN12 URIのセットを管理するためのグローバル変数。
// syncパッケージのMap構造体を使い、EAP-ID(uint8)をキー、紐付きURI(string)を格納することを想定している。
// ただし、書き込み(STORE)する際はanyで入ってくるので、読み出した(LOAD)valueを戻り値で使う場合は型アサーションが必要。
var eapIdTable sync.Map

// グローバル変数eapIdTableにおける対象idの読み込みを実行する。
// 引数はuint8型だが、これはlayer.EAP型の要素Idを引っ張ってくることを想定しているため。
// 戻り値はstringだが、sync.Loadメソッドの実行結果がanyで返ってくるので型アサーションを必要とする。
func eapIdTableLoad(eapid uint8) (string, bool) {
	var valueStr string
	value, ok := eapIdTable.Load(eapid)
	if ok {
		log.Printf("[EAP id table] LOAD / key: 0x%X / value: %v\n", eapid, value)
		valueAssertion, strOK := value.(string)
		if strOK {
			valueStr = valueAssertion
		} else {
			log.Printf("[EAP id table] LOAD / key: 0x%X / invalid value (not string)\n", eapid)
		}
	} else {
		log.Printf("[EAP id table] LOAD / key: 0x%X / value not found\n", eapid)
	}
	return valueStr, ok
}

// グローバル変数eapIdTableにおける対象idへの書き込みを実行する。
// 引数がuint8型なのはLoadと同じ事情。sync.Storeメソッドは戻り値がないのでこちらも同様。
// ただし、テーブル書き込みの際にRad-5GC GW設定の overwriteLinkString = true なら引数uristrの中身を一部上書きする。
// 具体的には、http://xxx.xxx.xxx.xxx:xxxxx/のxxx部分を設定項目ausfAddressで上書きする。
// しかし、引数に取ったuristrはany型のため、stringとして操作する前に型アサーションが必要となっている。
// また、書き込み前と後をログ出力したいため、sync.Loadメソッドで書き込み前にLOADしてvalueをログ出力させている。
func eapIdTableStore(eapid uint8, uristr any) error {
	var linkStringResult string
	var storeErr error
	value, ok := eapIdTable.Load(eapid)
	if ok {
		log.Printf("[EAP id table] LOAD / key: 0x%X / old value: %v\n", eapid, value)
	} else {
		log.Printf("[EAP id table] LOAD / key: 0x%X / value not found\n", eapid)
	}
	typeAssertion, strOK := uristr.(string)
	if strOK {
		if overwriteLinkString {
			afterStr, _ := strings.CutPrefix(typeAssertion, "http://")
			_, afterStrSecond, _ := strings.Cut(afterStr, "/")
			linkStringResult = "http://" + n12AUSFaddress + "/" + afterStrSecond
		} else {
			linkStringResult = typeAssertion
		}
		eapIdTable.Store(eapid, linkStringResult)
		log.Printf("[EAP id table] STORE / key: 0x%X / new value: %v\n", eapid, linkStringResult)
	} else {
		log.Printf("[EAP id table] STORE / key: 0x%X / failed - invalid value: %v", eapid, uristr)
		storeErrString := errors.New(fmt.Sprintln("invalid argument 2 / unknown type"))
		storeErr = storeErrString
	}
	return storeErr
}

// グローバル変数eapIdTableの対象idのkey/value消し込みを実行する。
// 引数がuint8型なのはLoadと同じ事情で、ログ出力のためsync.LoadAndDeleteを使う。
// キーが存在するなら（valueが何であれ）削除する処理なので、型アサーションは不要。
func eapIdTableDelete(eapid uint8) {
	value, ok := eapIdTable.LoadAndDelete(eapid)
	if ok {
		log.Printf("[EAP id table] DELETE / key: 0x%X / value: %v\n", eapid, value)
	} else {
		log.Printf("[EAP id table] DELETE / key: 0x%X / value not found\n", eapid)
	}
}
