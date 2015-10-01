package nuage

type Connection struct {
	Url     string
	Apivers string
	token   *Authtoken
}

type Authtoken struct {
	Apikey         string `json:"APIkey"`
	APIKeyExpiry   int64  `json:"APIKeyExpiry"`
	Id             string `json:"ID"`
	AvatarData     string `json:"avatarData"`
	AvatarType     string `json:"avatarType"`
	Email          string `json:"email"`
	EnterpriseID   string `json:"enterpriseID"`
	EnterpriseName string `json:"enterpriseName"`
	EntityScop     string `json:"entityScope"`
	ExternalID     string `json:"externalID"`
	ExternalId     string `json:"externalId"`
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	MobileNumber   string `json:"mobileNumber"`
	Password       string `json:"password"`
	Role           string `json:"role"`
	UserName       string `json:"userName"`
}
