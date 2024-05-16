package main

import (
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"gopkg.in/natefinch/lumberjack.v2"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/vendors/microsoft"
)

// バージョン表記
const rad5gcGWCurrentVer string = "0.7.5"

// 以下はinit()でrad5gcgwconf.yamlファイルから読み出して設定する
var sharedSecret string
var radiusAttributesLogOutputFlag bool
var allowedClientAddr string
var n12AUSFaddress string
var overwriteLinkString bool

// msgAuthOverwriteZeroは、チェック用MessageAuthenticatorの算出で16オクテットの0x00が必要なため、ベタ書きした。
var msgAuthOverwriteZero = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// Radiusサーバが使うハンドラの処理フラグ
type processingStatus struct {
	discardFlag bool
	errReason   string
	errString   error
}

// EAP-Identityでセットされる実体Identityを適切に分解して格納するための構造体。
type eapIdentiySet struct {
	identityPrefix string
	imsi           string
	networkName    string
}

func init() {
	fmt.Printf("[Rad-5GC GW] ver.%v reading configuration...\n", rad5gcGWCurrentVer)
	var readConfig rad5gcConfig
	readConfig, initErr := getRad5gcConfig()
	if initErr != nil {
		log.Fatalf("[Rad-5GC GW] reading configuration failed / %v\n", initErr)
	}
	log.SetOutput(&lumberjack.Logger{
		Filename:   readConfig.ConfFilename,
		MaxSize:    readConfig.ConfMaxSize,
		MaxBackups: readConfig.ConfMaxBackups,
		MaxAge:     readConfig.ConfMaxAge,
		LocalTime:  readConfig.ConfLocalTime,
		Compress:   readConfig.ConfCompress,
	})
	log.Println("--------------------")
	log.Printf("[Rad-5GC GW] ver.%v initializing...\n", rad5gcGWCurrentVer)
	sharedSecret = readConfig.ConfSharedSecret
	radiusAttributesLogOutputFlag = readConfig.ConfAttributesLogging
	allowedClientAddr = readConfig.ConfAllowedClientAddress
	n12AUSFaddress = readConfig.ConfAUSFaddress
	overwriteLinkString = readConfig.ConfOverwriteLinkString
}

func main() {
	handler := func(w radius.ResponseWriter, r *radius.Request) {
		var responsePacket *radius.Packet
		var eapSessionInfoId uint8
		var eapSessionInfoURI string
		eapPacket := new(layers.EAP)
		reqReceivedStatus := processingStatus{
			discardFlag: false,
		}
		// ハンドラ処理開始
		log.Printf("[RADIUS] %v (ID: 0x%v) received from %v\n", r.Packet.Code, r.Packet.Identifier, r.RemoteAddr)
		if radiusAttributesLogOutputFlag {
			for i := 0; i < len(r.Packet.Attributes); i++ {
				log.Printf("[RADIUS] Type %v : %X\n", i+1, r.Packet.Attributes[i].Type)
				log.Printf("[RADIUS] Attribute %v : %X\n", i+1, r.Packet.Attributes[i].Attribute)
			}
		}
		// 受信したRadiusパケットのSrcアドレス成否判定。NGならreqReceivedStatusでdiscardFlag:trueにする。
		if !reqReceivedStatus.discardFlag {
			checkAddr, _, _ := strings.Cut(r.RemoteAddr.String(), ":")
			if checkAddr != allowedClientAddr {
				reqReceivedStatus.discardFlag = true
				reqReceivedStatus.errReason = "[RADIUS] Client IP Address not Allowed : " + checkAddr
			}
		}
		// Proxy-State(33)の有無確認。
		// Accept/Challenge/Rejectでもそのまま載せる必要があるので、各種判定前であるこのタイミングで実行＆確保しておく。
		var attr33 map[int][]byte
		var attr33Exist bool
		if !reqReceivedStatus.discardFlag {
			attrSet, attrExist := multiAttrGet(r.Packet, 33)
			attr33 = attrSet
			attr33Exist = attrExist
		}
		// EAP-Messageが含まれているか確認。含まれているならeapPacketに(layer.EAP型で)格納される。
		// ※初期実装では、EAP-Message含まれていない場合にここで nil dereference exception発生するかも。実際に発生したら改修予定。
		// 確認するためのisEAPMessageIncludedはprocessingStatusを返すので、EAP-MessageがなければdiscardFlag:trueで返ってくる。
		if !reqReceivedStatus.discardFlag {
			psCheck, pkt, includedErr := isEAPMessageIncluded(r)
			if includedErr != nil {
				reqReceivedStatus = psCheck
				log.Printf("%v: %v", reqReceivedStatus.errReason, reqReceivedStatus.errString)
			} else {
				reqReceivedStatus = psCheck
				eapPacket = pkt
			}
		}
		// EAP Typeから後続処理を判定する。
		// EAP-Identity/EAP-AKA'/それ以外/の3グループに分岐し、EAP-IdentityはID Prefixで、EAP-AKA'はEAP SubTypeでさらに分岐する。
		if !reqReceivedStatus.discardFlag {
			switch compareEapType := eapPacket.Type; compareEapType {
			case 1:
				switch idPrefixCheckSet := eapIdentityByteToString(eapPacket); idPrefixCheckSet.identityPrefix {
				case "6":
					nwName, nwNameErr := toNWNameForN12(idPrefixCheckSet.networkName)
					if nwNameErr != nil {
						log.Printf("%v\n", nwNameErr)
						reqReceivedStatus.discardFlag = true
						reqReceivedStatus.errReason = "Failed to assemble Network name for N12."
						reqReceivedStatus.errString = nwNameErr
					} else {
						var supi string = "imsi-" + idPrefixCheckSet.imsi
						authRespFirstStCode, authRespFirstBodyStr, authReqFirstErr := authReqFirst(supi, nwName)
						if authReqFirstErr != nil {
							log.Printf("%v\n", authReqFirstErr)
							reqReceivedStatus.discardFlag = true
							reqReceivedStatus.errReason = "Failed to send N12 AuthenticationRequest."
							reqReceivedStatus.errString = authReqFirstErr
						} else {
							authRespFirstEapPayload, authRespFirstEapId, linkStr, respBodyDecodeErr := authRespBodyDecode(authRespFirstStCode, authRespFirstBodyStr)
							if respBodyDecodeErr != nil {
								reqReceivedStatus.discardFlag = true
								reqReceivedStatus.errReason = "Failed to decode response body(N12 AuthenticationResponse)"
								reqReceivedStatus.errString = respBodyDecodeErr
							} else {
								switch authRespFirstStCode {
								case 201:
									var code radius.Code = radius.CodeAccessChallenge
									log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
									accessChallengeAKAchallenge := r.Response(code)
									accessChallengeAKAchallenge.Attributes.Add(79, authRespFirstEapPayload)
									responsePacket = accessChallengeAKAchallenge
									eapSessionInfoId = authRespFirstEapId
									eapSessionInfoURI = linkStr
								case 400, 403, 404, 500, 501, 503:
									var code radius.Code = radius.CodeAccessReject
									accessRejectRespFirstProblem := r.Response(code)
									log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
									responsePacket = accessRejectRespFirstProblem
									log.Printf("Response code %v / %v", authRespFirstStCode, linkStr)
								default:
									var code radius.Code = radius.CodeAccessReject
									accessRejectRespFirstUnsupportedStCode := r.Response(code)
									log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
									responsePacket = accessRejectRespFirstUnsupportedStCode
									log.Printf("Response code %v not supported", authRespFirstStCode)
								}
							}
						}
					}
				case "7", "8":
					var code radius.Code = radius.CodeAccessChallenge
					log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
					challengeRespAKAidentityReq := r.Response(code)
					// AT_FULLAUTH_ID_REQを直接生成
					var attributeAKAidentityReq = []byte{0x01, 0x00, 0x00, 0x0c, 0x32, 0x05, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00}
					var eapSessionId byte = generateEAPId()
					attributeAKAidentityReq[1] = eapSessionId
					challengeRespAKAidentityReq.Attributes.Add(79, attributeAKAidentityReq)
					responsePacket = challengeRespAKAidentityReq
				default:
					var code radius.Code = radius.CodeAccessReject
					rejectResponseUnknownId := r.Response(code)
					log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
					var rejectResponseNotIdentifiedReplyString string = fmt.Sprintf("Unknown identity : %v", idPrefixCheckSet.identityPrefix)
					log.Printf("[RADIUS] Unknown identity : %v%v%v\n", idPrefixCheckSet.identityPrefix, idPrefixCheckSet.imsi, idPrefixCheckSet.networkName)
					err := rfc2865.ReplyMessage_AddString(rejectResponseUnknownId, rejectResponseNotIdentifiedReplyString)
					if err != nil {
						reqReceivedStatus.discardFlag = true
						reqReceivedStatus.errReason = "Failed to add Reply-Message."
						reqReceivedStatus.errString = err
					} else {
						responsePacket = rejectResponseUnknownId
					}
				}
			case 50:
				// TypeData先頭byte(EAP Subtype)を見て、1/2/4/5/default で分岐する。
				// さらにSubtype 1(AKA-Challenge)受信時は、AUSFから返ってきたEAP-Messageで処理が分岐する。
				switch compareEapSubType := eapPacket.TypeData[0]; compareEapSubType {
				case 1:
					log.Printf("[EAP] EAP SubType : %v / AKA'-Challenge received\n", compareEapSubType)
					authRespExchStCode, authRespExchBodyStr, authRespExchErr := authReqExchange(eapPacket.Contents)
					if authRespExchErr != nil {
						eapIdTableDelete(eapPacket.Id)
						reqReceivedStatus.discardFlag = true
						reqReceivedStatus.errReason = "N12 Authentication Response failure."
						reqReceivedStatus.errString = authRespExchErr
					} else {
						eapIdTableDelete(eapPacket.Id)
						exchEapPayload, exchEapId, exchResultStr, exchErr := authRespBodyDecode(authRespExchStCode, authRespExchBodyStr)
						if exchErr != nil {
							reqReceivedStatus.discardFlag = true
							reqReceivedStatus.errReason = "N12 Authentication Response body decoding failure."
							reqReceivedStatus.errString = exchErr
						} else {
							switch compareEapMsg := exchEapPayload[0]; compareEapMsg {
							case 1:
								var code radius.Code = radius.CodeAccessChallenge
								log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
								accessChallengeAKAchallenge := r.Response(code)
								accessChallengeAKAchallenge.Attributes.Add(79, exchEapPayload)
								responsePacket = accessChallengeAKAchallenge
								log.Println("[EAP] EAP request / AKA-Challenge")
								eapSessionInfoId = exchEapId
								eapSessionInfoURI = exchResultStr
							case 3:
								var code radius.Code = radius.CodeAccessAccept
								log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
								accessAcceptEAPSuccess := r.Response(code)
								accessAcceptEAPSuccess.Attributes.Add(79, exchEapPayload)
								log.Printf("[EAP] EAP Success / Kseaf : %v\n", exchResultStr)
								// MS-MPPE send/recv key generation and Attribute Addition
								// 標準仕様上MSKではなくKseafが入るので、暫定でKseaf文字列を半分に割って32byteずつ入れる。
								// おそらく無線LAN側でPMK作れない（ここは長期的課題とする。3GPP Release 17 NSWOF機能取り込みとセット）
								msMPPEsendKeySrc := []byte(exchResultStr)[0:32]
								msMPPErecvKeySrc := []byte(exchResultStr)[32:64]
								sendKeyErr := microsoft.MSMPPESendKey_Set(accessAcceptEAPSuccess, msMPPEsendKeySrc)
								if sendKeyErr != nil {
									log.Println("[RADIUS] Fail to set MSMPPESendKey")
								}
								recvKeyErr := microsoft.MSMPPERecvKey_Set(accessAcceptEAPSuccess, msMPPErecvKeySrc)
								if recvKeyErr != nil {
									log.Println("[RADIUS] Fail to set MSMPPErecvKey")
								}
								responsePacket = accessAcceptEAPSuccess
							case 4:
								var code radius.Code = radius.CodeAccessReject
								log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
								accessRejectEAPfailure := r.Response(code)
								accessRejectEAPfailure.Attributes.Add(79, exchEapPayload)
								log.Printf("[EAP] EAP Failure / authResult : %v\n", exchResultStr)
								responsePacket = accessRejectEAPfailure
							default:
								reqReceivedStatus.discardFlag = true
								reqReceivedStatus.errReason = "invalid EAP-Message from AUSF"
								reqReceivedStatus.errString = errors.New("invalid eap-message from ausf")
								log.Println("[Rad-5GC GW] invalid EAP-Message from AUSF")
							}
						}
					}
				case 2:
					log.Printf("[EAP] EAP SubType : %v / AKA-Authentication-Reject\n", compareEapSubType)
					authRespExchStCode, authRespExchBodyStr, authRespExchErr := authReqExchange(eapPacket.Contents)
					if authRespExchErr != nil {
						eapIdTableDelete(eapPacket.Id)
						reqReceivedStatus.discardFlag = true
						reqReceivedStatus.errReason = "N12 Authentication Response failure."
						reqReceivedStatus.errString = authRespExchErr
					} else {
						eapIdTableDelete(eapPacket.Id)
						exchEapPayload, exchEapId, exchResultStr, exchErr := authRespBodyDecode(authRespExchStCode, authRespExchBodyStr)
						if exchErr != nil {
							reqReceivedStatus.discardFlag = true
							reqReceivedStatus.errReason = "N12 Authentication Response body decoding failure."
							reqReceivedStatus.errString = exchErr
						} else {
							var code radius.Code = radius.CodeAccessReject
							log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
							accessRejectEAPfailure := r.Response(code)
							accessRejectEAPfailure.Attributes.Add(79, exchEapPayload)
							log.Printf("[EAP] EAP Failure(0x%v) / authResult : %v\n", exchEapId, exchResultStr)
							responsePacket = accessRejectEAPfailure
						}
					}
				case 4:
					log.Printf("[EAP] EAP SubType : %v / AKA-Synchronization-Failure\n", compareEapSubType)
					authRespExchStCode, authRespExchBodyStr, authRespExchErr := authReqExchange(eapPacket.Contents)
					if authRespExchErr != nil {
						eapIdTableDelete(eapPacket.Id)
						reqReceivedStatus.discardFlag = true
						reqReceivedStatus.errReason = "N12 Authentication Response failure."
						reqReceivedStatus.errString = authRespExchErr
					} else {
						eapIdTableDelete(eapPacket.Id)
						exchEapPayload, exchEapId, exchResultStr, exchErr := authRespBodyDecode(authRespExchStCode, authRespExchBodyStr)
						if exchErr != nil {
							reqReceivedStatus.discardFlag = true
							reqReceivedStatus.errReason = "N12 Authentication Response body decoding failure."
							reqReceivedStatus.errString = exchErr
						} else {
							switch compareEapMsg := exchEapPayload[0]; compareEapMsg {
							case 1:
								var code radius.Code = radius.CodeAccessChallenge
								log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
								accessChallengeAKAchallenge := r.Response(code)
								accessChallengeAKAchallenge.Attributes.Add(79, exchEapPayload)
								responsePacket = accessChallengeAKAchallenge
								log.Println("[EAP] EAP request / AKA-Challenge")
								eapSessionInfoId = exchEapId
								eapSessionInfoURI = exchResultStr
							case 4:
								var code radius.Code = radius.CodeAccessReject
								log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
								accessRejectEAPfailure := r.Response(code)
								accessRejectEAPfailure.Attributes.Add(79, exchEapPayload)
								log.Printf("[EAP] EAP Failure / authResult : %v\n", exchResultStr)
								responsePacket = accessRejectEAPfailure
							default:
								reqReceivedStatus.discardFlag = true
								reqReceivedStatus.errReason = "invalid EAP-Message from AUSF"
								reqReceivedStatus.errString = errors.New("invalid eap-message from ausf")
								log.Println("[Rad-5GC GW] invalid EAP-Message from AUSF")
							}
						}
					}
				case 5:
					log.Printf("[EAP] EAP SubType : %v / AKA-Identity\n", compareEapSubType)
					var eapRespAKAidentitySet eapIdentiySet
					eapRespAKAidentitySet.identityPrefix = string(eapPacket.TypeData[7])
					eapRespAKAidentitySet.imsi = string(eapPacket.TypeData[8:23])
					eapRespAKAidentitySet.networkName = string(eapPacket.TypeData[23:])
					nwName, nwNameErr := toNWNameForN12(eapRespAKAidentitySet.networkName)
					if nwNameErr != nil {
						log.Printf("%v\n", nwNameErr)
						reqReceivedStatus.discardFlag = true
						reqReceivedStatus.errReason = "Failed to assemble Network name for N12."
						reqReceivedStatus.errString = nwNameErr
					} else {
						authRespFirstStCode, authRespFirstBodyStr, authReqFirstErr := authReqFirst(eapRespAKAidentitySet.imsi, nwName)
						if authReqFirstErr != nil {
							log.Printf("%v\n", authReqFirstErr)
							reqReceivedStatus.discardFlag = true
							reqReceivedStatus.errReason = "Failed to send N12 AuthenticationRequest."
							reqReceivedStatus.errString = nwNameErr
						} else {
							authRespFirstEapPayload, authRespFirstEapId, linkStr, respBodyDecodeErr := authRespBodyDecode(authRespFirstStCode, authRespFirstBodyStr)
							if respBodyDecodeErr != nil {
								reqReceivedStatus.discardFlag = true
								reqReceivedStatus.errReason = "Failed to decode response body(N12 AuthenticationResponse)"
								reqReceivedStatus.errString = respBodyDecodeErr
							} else {
								var code radius.Code = radius.CodeAccessChallenge
								log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
								accessChallengeAKAchallenge := r.Response(code)
								accessChallengeAKAchallenge.Attributes.Add(79, authRespFirstEapPayload)
								responsePacket = accessChallengeAKAchallenge
								eapSessionInfoId = authRespFirstEapId
								eapSessionInfoURI = linkStr
							}
						}
					}
				default:
					var code radius.Code = radius.CodeAccessReject
					log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
					rejectResponseEapTypeUnsupEAPsub := r.Response(code)
					var rejectResponseEapSubTypeUnsupReplyString string = fmt.Sprintf("EAP AttributeType (0x%v) is not supported.", compareEapSubType)
					err := rfc2865.ReplyMessage_AddString(rejectResponseEapTypeUnsupEAPsub, rejectResponseEapSubTypeUnsupReplyString)
					if err != nil {
						reqReceivedStatus.discardFlag = true
						reqReceivedStatus.errReason = "Failed to add Reply-Message."
						reqReceivedStatus.errString = err
						eapIdTableDelete(eapPacket.Id)
					} else {
						responsePacket = rejectResponseEapTypeUnsupEAPsub
						log.Printf("[EAP] EAP SubType (0x%v) is not supported.\n", compareEapSubType)
						eapIdTableDelete(eapPacket.Id)
					}
				}
			default:
				var code radius.Code = radius.CodeAccessReject
				log.Printf("[RADIUS] writing %v to %v\n", code, r.RemoteAddr)
				rejectResponseEapTypeUnsupEAP := r.Response(code)
				var rejectResponseEapTypeUnsupReplyString string = fmt.Sprintf("EAP SubType (%v) is not supported.", eapPacket.Type)
				err := rfc2865.ReplyMessage_AddString(rejectResponseEapTypeUnsupEAP, rejectResponseEapTypeUnsupReplyString)
				if err != nil {
					reqReceivedStatus.discardFlag = true
					reqReceivedStatus.errReason = "Failed to add Reply-Message."
					reqReceivedStatus.errString = err
				} else {
					responsePacket = rejectResponseEapTypeUnsupEAP
				}
			}
		}
		// 上記のResponseパケット生成処理の最終段階として、Proxy-StateとMessage-Authenticator付与処理を実行する。
		// responsePacketが生成されていなければスルー。
		if responsePacket != nil {
			if attr33Exist {
				for _, v := range attr33 {
					responsePacket.Attributes.Add(33, v)
				}
			}
			responsePacket.Attributes.Add(80, msgAuthOverwriteZero)
			calculatedMAC, _, psCalcMAC := messageAuthenticatorCalc(responsePacket, []byte(sharedSecret))
			if psCalcMAC.errString != nil {
				reqReceivedStatus = psCalcMAC
			} else {
				responsePacket.Attributes.Set(80, calculatedMAC)
			}
		}
		// discardFlagが false のままたどり着けば、受信したAccess-Requestに対するresponse系RADIUSメッセージがここで返送される。
		if !reqReceivedStatus.discardFlag {
			writingErr := w.Write(responsePacket)
			if writingErr != nil {
				log.Printf("[RADIUS] Failed to send Response packet / %v\n", writingErr)

			} else {
				log.Printf("[RADIUS] %v (ID:0x%v) send to %v\n", responsePacket.Code, responsePacket.Identifier, r.RemoteAddr)
				if eapSessionInfoURI != "" {
					tableStoreErr := eapIdTableStore(eapSessionInfoId, eapSessionInfoURI)
					if tableStoreErr != nil {
						log.Printf("%v", tableStoreErr)
					}
				}
			}
		}
		// discardFlagがどこかで true になったら、最終的にはここの処理にたどり着く（はず）
		if reqReceivedStatus.discardFlag {
			log.Printf("[RADIUS] %v (ID: %v) is silently discarded.\n", r.Packet.Code, r.Packet.Identifier)
			log.Printf("[RADIUS] %v / %v\n", reqReceivedStatus.errReason, reqReceivedStatus.errString)
		}
	}
	// Radius Serverに対するハンドラと共有秘密鍵の適用
	server := radius.PacketServer{
		Handler:      radius.HandlerFunc(handler),
		SecretSource: radius.StaticSecretSource([]byte(sharedSecret)),
	}
	// 上記のRadius Serverを指定してRad-5GC GW起動
	fmt.Println("[Rad-5GC GW] Activation success and start.")
	log.Println("[Rad-5GC GW] Activation success and start.")
	if rad5gcGWStartErr := server.ListenAndServe(); rad5gcGWStartErr != nil {
		log.Println("[Rad-5GC GW] Activation failed.")
		log.Fatal(rad5gcGWStartErr)
	}
}

// 〜〜〜〜〜〜〜〜〜〜　ここからファクトリ関数　〜〜〜〜〜〜〜〜〜〜

// Proxy-StateやEAP-Messageなど、同一Typeに複数のAttributeが存在する場合のAttritube抽出を行う。
// 引数に対象RadiusパケットとType値(radius.Type型だが実質的にint)を指定する。
// 指定したTypeが存在しない場合、nilとfalseが返る。存在すれば、map型で値が戻ってtrueが入る。
func multiAttrGet(rp *radius.Packet, t radius.Type) (map[int][]byte, bool) {
	attrSet := map[int][]byte{}
	var isExist bool
	num := 0
	for in := 0; in < len(rp.Attributes); in++ {
		if rp.Attributes[in].Type == t {
			attrSet[num] = rp.Attributes[in].Attribute
			num++
		}
	}
	if len(attrSet) > 0 {
		isExist = true
	}
	return attrSet, isExist
}

// radiusパケットからEAP-Message有無を確認し、あればeapPacketSourceにデコード結果（のlayers.EAP構造体）を返す。戻り値ps.discardFlag:falseを明示。
// なければEAP-Messageなし＋ps.discardFlag:trueを返す。
// EAP-Messageが有る場合のMessage-Authenticatorチェックも入れている。
func isEAPMessageIncluded(r *radius.Request) (processingStatus, *layers.EAP, error) {
	ps := processingStatus{}
	eapPacketSource := new(layers.EAP)
	var df gopacket.DecodeFeedback
	var returnAttr79 radius.Attribute
	returnAttr79, _ = r.Packet.Attributes.Lookup(79)
	if returnAttr79 != nil {
		log.Printf("[EAP] EAP-Message: %X", returnAttr79)
		_, msgAuthCheckResult, msgAuthCheckPs := messageAuthenticatorCalc(r.Packet, []byte(sharedSecret))
		if msgAuthCheckResult {
			if err := eapPacketSource.DecodeFromBytes(returnAttr79, df); err != nil {
				ps.discardFlag = true
				ps.errReason = "EAP Packet decoding failure"
				ps.errString = err
			} else {
				ps.discardFlag = false
				log.Printf("[EAP] Code: 0x%X, Id: 0x%X, Length: 0x%X, EAPType: 0x%X\n", eapPacketSource.Code, eapPacketSource.Id, eapPacketSource.Length, eapPacketSource.Type)
				log.Printf("[EAP] TypeData: %X\n", eapPacketSource.TypeData)
				// log.Printf("EAP layer contents : 0x%X\n", eapPacketSource.BaseLayer.Contents)
			}
		} else {
			ps.discardFlag = msgAuthCheckPs.discardFlag
			ps.errReason = msgAuthCheckPs.errReason
			ps.errString = msgAuthCheckPs.errString
		}
	} else {
		ps.discardFlag = true
		ps.errReason = "EAP-Message not found."
		ps.errString = fmt.Errorf("no EAP-Message %v", ps.errString)
	}
	return ps, eapPacketSource, ps.errString
}

// Responseに入れるMessage-Authenticatorの算出にも使い回せるようにできている、はず。
// Message-Authenticatorを持たないRadiusパケットを引数に取るとmsgAuthNotFoundErrを返すようにしている。
// EAP-Messageを持たないパケットにMessage-Authenticatorを追加したい場合は、radius.Attributes.Addメソッドで事前にAVP自体を追加しておくこと。
func messageAuthenticatorCalc(rp *radius.Packet, sharedSecret []byte) ([]byte, bool, processingStatus) {
	var resultErrStrings error
	var ps processingStatus
	messageAuthenticator, msgAuthNotFoundErr := rfc2869.MessageAuthenticator_Lookup(rp)
	if msgAuthNotFoundErr != nil {
		resultErrStrings = msgAuthNotFoundErr
	}
	var chPkt *radius.Packet = rp
	chPkt.Attributes.Set(80, msgAuthOverwriteZero)
	chBytes, chBytesErr := chPkt.MarshalBinary()
	if chBytesErr != nil {
		resultErrStrings = chBytesErr
	}
	mac := hmac.New(md5.New, sharedSecret)
	mac.Write(chBytes)
	expectedMAC := mac.Sum(nil)
	result := hmac.Equal(expectedMAC, messageAuthenticator)
	switch {
	case resultErrStrings == msgAuthNotFoundErr:
		ps.discardFlag = true
		ps.errReason = "AVP Message-Authenticator not found."
		ps.errString = msgAuthNotFoundErr
	case resultErrStrings == chBytesErr:
		ps.discardFlag = true
		ps.errReason = "Packet marshaling error."
		ps.errString = chBytesErr
	case !result:
		ps.discardFlag = true
		ps.errReason = "Message-Authenticator not matched."
		ps.errString = errors.New("invalid message authenticator")
	}
	return expectedMAC, result, ps
}

// EAPパケットでEAP-Type:Identity(1)が来ているとき、EAPパケット内のTypeDataの長さをチェックして
// 適切(Prefix:1byte/IMSI:15byte/NAI:35byte)ならeapIdentiySet型にして返す。
// そうでなければ、元EAPパケットのTypeDataをstringにしてidentityPrefixに詰め込み、他を""(ゼロ値)にしてeapIdentiySet型で返す。
func eapIdentityByteToString(p *layers.EAP) eapIdentiySet {
	var set eapIdentiySet
	if len(p.TypeData) == 51 {
		set.identityPrefix = string(p.TypeData[0])
		set.imsi = string(p.TypeData[1:16])
		set.networkName = string(p.TypeData[16:])
	} else {
		set.identityPrefix = string(p.TypeData)
		set.imsi = ""
		set.networkName = ""
	}
	return set
}

// 最初のEAP-Response/AKA-identtyで仮名・高速再認証のIdentityPrefixが来たケースで、FullAuthで差し戻すためのEAP-Request用IDを生成するためのもの。
// AUSFから返ってくるEAP-RequestのEAP-IDと衝突しないよう、ランダムId生成後にグローバル変数eapIdTableをチェックして使用中だったら再生成に入る。
func generateEAPId() byte {
	var generatedId byte
	for {
		seed := time.Now().UnixNano()
		randGenerator := rand.New(rand.NewSource(seed))
		zeroToFFInt := randGenerator.Intn(255)
		_, ok := eapIdTableLoad(byte(zeroToFFInt))
		if !ok {
			generatedId = byte(zeroToFFInt)
			break
		}
	}
	return generatedId
}

// 最初のN12 AuthenticationRequestを送信するための引数ServingNetworkNameを作成するための関数。
// 構造体eapIdentiySet.networkNameを引数に取ることを想定している。
func toNWNameForN12(str string) (string, error) {
	var nwNameErr error
	var modifiedStr string
	if strings.HasPrefix(str, "@wlan.") && strings.HasSuffix(str, ".3gppnetwork.org") {
		cutStr, _ := strings.CutPrefix(str, "@wlan.")
		modifiedStr = "5G:" + cutStr
	} else {
		err := errors.New("invalid network name")
		nwNameErr = err
	}
	return modifiedStr, nwNameErr
}
