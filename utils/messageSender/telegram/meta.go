package telegram

type Addition struct {
	BotToken            string `json:"bot_token" required:"true"`
	ChatID              string `json:"chat_id" required:"true"`
	MessageThreadID     string `json:"message_thread_id" help:"Optional. Unique identifier of a message thread to which the message belongs; for supergroups only"`
	Endpoint            string `json:"endpoint" required:"true" default:"https://api.telegram.org/bot" help:"Telegram API endpoint, default is https://api.telegram.org/bot"`
	CommandMenuEnabled  bool   `json:"command_menu_enabled" default:"false" help:"Enable the centralized Telegram command menu on this Komari server"`
	CommandAllowedUsers string `json:"command_allowed_users" help:"Comma-separated Telegram numeric user IDs allowed to use commands. Strongly recommended for groups"`
	CommandTimezone     string `json:"command_timezone" default:"Asia/Shanghai" help:"IANA timezone used by today/yesterday traffic commands"`
}
