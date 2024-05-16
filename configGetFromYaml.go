package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type rad5gcConfig struct {
	ConfFilename             string `yaml:"filename"`
	ConfMaxSize              int    `yaml:"maxSize"`
	ConfMaxBackups           int    `yaml:"maxBackups"`
	ConfMaxAge               int    `yaml:"maxAge"`
	ConfLocalTime            bool   `yaml:"localTime"`
	ConfCompress             bool   `yaml:"compress"`
	ConfSharedSecret         string `yaml:"sharedSecret"`
	ConfAllowedClientAddress string `yaml:"allowedClientAddress"`
	ConfAttributesLogging    bool   `yaml:"attributesLogging"`
	ConfAUSFaddress          string `yaml:"ausfAddress"`
	ConfOverwriteLinkString  bool   `yaml:"overwriteLinkString"`
}

func getRad5gcConfig() (rad5gcConfig, error) {
	var configSet rad5gcConfig
	var getConfigFileErr error
	// カレントディレクトリの confrad5gcgw.yaml を決め打ちとしている。
	rf, filereadErr := os.ReadFile("confrad5gcgw.yaml")
	if filereadErr != nil {
		getConfigFileErr = filereadErr
		log.Printf("[CONFIG] error: %v\n", getConfigFileErr)
	}
	// 読み込んだ rad5gcgwconf.yaml を rad5gcConfig型の構造体に流し込む。
	unmarshalErr := yaml.Unmarshal(rf, &configSet)
	if unmarshalErr != nil {
		getConfigFileErr = unmarshalErr
		log.Printf("[CONFIG] error: %v\n", getConfigFileErr)
	}
	if len(configSet.ConfSharedSecret) > 258 || len(configSet.ConfSharedSecret) < 1 {
		getConfigFileErr = errors.New("shared secret is too short or long")
		log.Printf("[CONFIG] error: %v\n", getConfigFileErr)
	} else {
		fmt.Println("[CONFIG] Shared Secret : length OK ")
	}
	if nil == net.ParseIP(configSet.ConfAllowedClientAddress) {
		getConfigFileErr = errors.New("invalid client Address")
		log.Printf("[CONFIG] error: %v\n", getConfigFileErr)
	} else {
		fmt.Println("[CONFIG] Allowed Client Address : validation check OK")
	}
	fmt.Printf("[CONFIG] Radius Attributes Logging: %v\n", configSet.ConfAttributesLogging)
	ausfAddrCheck, ausfPort, sepCheck := strings.Cut(configSet.ConfAUSFaddress, ":")
	ausfPortCheck, _ := strconv.Atoi(ausfPort)
	if nil == net.ParseIP(ausfAddrCheck) || ausfPortCheck > 65535 || ausfPortCheck < 0 || !sepCheck {
		getConfigFileErr = errors.New("invalid AUSF address or Port number")
		log.Printf("[CONFIG] error: %v\n", getConfigFileErr)
	} else {
		fmt.Println("[CONFIG] AUSF address : validation check OK")
	}
	fmt.Printf("[CONFIG] Overwrite Link String: %v\n", configSet.ConfOverwriteLinkString)
	fmt.Println("----------")
	return configSet, getConfigFileErr
}
