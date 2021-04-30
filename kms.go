package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"regexp"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

func Sign(ctx context.Context, keyResourceID string, payload []byte) ([]byte, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256(payload)
	digestSlice := digest[:]
	req := &kmspb.AsymmetricSignRequest{
		Name: keyResourceID,
		Digest: &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{Sha256: digestSlice},
		},
	}

	resp, err := client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.Signature, nil
}

func GetPublicKey(ctx context.Context, keyResourceID string) (*kmspb.PublicKey, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	req := &kmspb.GetPublicKeyRequest{
		Name: keyResourceID,
	}

	return client.GetPublicKey(ctx, req)
}

func KeyResourceIDToKid(keyResourceId string) (string, error) {
	// Key Resource ID format: projects/{project_id}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
	re := regexp.MustCompile("projects/(.+)/locations/(.+)/keyRings/(.+)/cryptoKeys/(.+)/cryptoKeyVersions/(.+)")
	matched := re.FindStringSubmatch(keyResourceId)
	if len(matched) != 6 {
		return "", errors.New("invalid key resource id")
	}
	return matched[5], nil
}
