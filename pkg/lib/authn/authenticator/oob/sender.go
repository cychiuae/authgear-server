package oob

import (
	"github.com/authgear/authgear-server/pkg/lib/authn"
	"github.com/authgear/authgear-server/pkg/lib/authn/otp"
)

type OTPMessageSender interface {
	SendEmail(email string, opts otp.SendOptions) error
	SendSMS(phone string, opts otp.SendOptions) error
}

type CodeSender struct {
	OTPMessageSender OTPMessageSender
}

func (s *CodeSender) SendCode(
	channel authn.AuthenticatorOOBChannel,
	target string,
	code string,
	messageType otp.MessageType,
) (result *otp.CodeSendResult, err error) {
	opts := otp.SendOptions{
		OTP:         code,
		URL:         "", // TODO(interaction): Include login link in email.
		MessageType: messageType,
	}
	switch channel {
	case authn.AuthenticatorOOBChannelEmail:
		err = s.OTPMessageSender.SendEmail(target, opts)
	case authn.AuthenticatorOOBChannelSMS:
		err = s.OTPMessageSender.SendSMS(target, opts)
	default:
		panic("oob: unknown channel type: " + channel)
	}

	if err != nil {
		return
	}

	result = &otp.CodeSendResult{
		Target:       target,
		Channel:      string(channel),
		CodeLength:   len(code),
		SendCooldown: OOBOTPSendCooldownSeconds,
	}
	return
}
