package version

import (
	"fmt"

	apk "github.com/knqyf263/go-apk-version"
)

type apkVersion struct {
	obj apk.Version
}

func newApkVersion(raw string) (*apkVersion, error) {
	ver, err := apk.NewVersion(raw)
	if err != nil {
		return nil, err
	}

	return &apkVersion{
		obj: ver,
	}, nil
}

func (a *apkVersion) Compare(other *Version) (int, error) {
	if other.Format != ApkFormat {
		return -1, fmt.Errorf("unable to compare apk to given format: %s", other.Format)
	}
	if other.rich.apkVer == nil {
		return -1, fmt.Errorf("given empty apkVersion object")
	}

	return other.rich.apkVer.obj.Compare(a.obj), nil

}
