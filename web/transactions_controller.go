package web

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"
	"github.com/manyminds/api2go/jsonapi"
	"github.com/smartcontractkit/chainlink/services"
	"github.com/smartcontractkit/chainlink/store/orm"
	"github.com/smartcontractkit/chainlink/store/presenters"
)

// TransactionsController displays Ethereum transactions requests.
type TransactionsController struct {
	App services.Application
}

// Show returns the details of a Ethereum Transasction details.
// Example:
//  "<application>/transactions/:TxHash"
func (tc *TransactionsController) Show(c *gin.Context) {
	hash := common.HexToHash(c.Param("TxHash"))
	if tx, err := tc.App.GetStore().FindTxByAttempt(hash); err == orm.ErrorNotFound {
		c.AbortWithError(404, errors.New("Transaction not found"))
	} else if err != nil {
		c.AbortWithError(500, err)
	} else if doc, err := jsonapi.Marshal(presenters.Tx{Tx: tx}); err != nil {
		c.AbortWithError(500, err)
	} else {
		c.Data(200, MediaType, doc)
	}
}
