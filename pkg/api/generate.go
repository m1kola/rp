package api

//go:generate go run ../../vendor/github.com/alvaroloes/enumer -type InstallPhase -output zz_generated_installphase_enumer.go

//go:generate go run ../../vendor/github.com/golang/mock/mockgen -destination=../uti/mocks/mock_$GOPACKAGE/$GOPACKAGE.go github.com/jim-minter/rp/pkg/$GOPACKAGE Version
//go:generate go run ../../vendor/golang.org/x/tools/cmd/goimports -local=github.com/jim-minter/rp -e -w ../uti/mocks/mock_$GOPACKAGE/$GOPACKAGE.go
