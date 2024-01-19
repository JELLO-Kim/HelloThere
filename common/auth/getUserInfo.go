package auth

import (
	"github.com/pkg/errors"
)

func getUserInfo(token string) (err error) {
	var (
		loginId  string
		tokenErr error
	)
	// 토큰정보 없고, 비회원 유저도 사용가능한지 확인
	if token == "" {
		err = errors.New("로그인 필요")
	}
	// header 토큰으로부터 creator 정보 가져오기
	loginId, tokenErr = hashToken(token)
	if loginId == "" && tokenErr == nil {
		//clog.Error = tokenErr
		//clog.Description = "JWT 토큰을 받아올 수 없음"
		return
	}

	if tokenErr != nil {
		err = errors.New("[로그인 정보 오류] 접근 권한이 없습니다.")
		return
	}
	return
}
