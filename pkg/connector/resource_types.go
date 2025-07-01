package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

// The user resource type is for all user objects from the database.
var (
	accountResourceType = &v2.ResourceType{
		Id:          "account",
		DisplayName: "Account",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
	}
	roleResourceType = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE},
	}
)
