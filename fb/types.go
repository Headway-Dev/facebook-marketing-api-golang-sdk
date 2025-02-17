package fb

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// ErrorContainer is a convenient type for embedding in other structs.
type ErrorContainer struct {
	Error *Error `json:"error"`
}

// GetError returns an error if available.
func (ec *ErrorContainer) GetError() error {
	if ec.Error != nil {
		return ec.Error
	}

	return nil
}

type listResponse struct {
	Paging
	Data json.RawMessage `json:"data"`
}

type listElementsResponse struct {
	Paging
	Data []json.RawMessage `json:"data"`
}

// Error implements error.
type Error struct {
	Message        string          `json:"message"`
	Type           string          `json:"type"`
	Code           uint64          `json:"code"`
	ErrorSubcode   uint64          `json:"error_subcode"`
	FbtraceID      string          `json:"fbtrace_id"`
	IsTransient    bool            `json:"is_transient"`
	ErrorUserTitle string          `json:"error_user_title"`
	ErrorUserMsg   string          `json:"error_user_msg"`
	ErrorData      json.RawMessage `json:"error_data"`
}

// IsNotFound returns whether the error is a fb error with specific code and subcode.
func IsNotFound(err error) bool {
	e, ok := err.(*Error)
	if !ok {
		return false
	}
	if e == nil {
		return false
	}

	return e.Code == 100 && e.ErrorSubcode == 33
}

// Error implements error.
func (e *Error) Error() string {
	if e.ErrorUserMsg != "" {
		return e.ErrorUserMsg
	}

	return fmt.Sprintf("facebook: type='%s' message='%s' error_user_title='%s'", e.Type, e.Message, e.ErrorUserTitle)
}

// TimeRange is the standard time range used by facebook.
type TimeRange struct {
	Since string `json:"since"`
	Until string `json:"until"`
}

// Paging is a convenient type for embedding in other structs.
type Paging struct {
	Paging struct {
		Cursors struct {
			Before string `json:"before"`
			After  string `json:"after"`
		} `json:"cursors"`
		Next string `json:"next"`
	} `json:"paging"`
}

// KeyValue represents a Facebook k/v entry in a API JSON response.
type KeyValue struct {
	ActionType string      `json:"action_type"`
	Value      json.Number `json:"value"`
}

// ID contains the ID field.
type ID struct {
	ID string `json:"id"`
}

// MetadataContainer contains a graph APIs object metadata.
type MetadataContainer struct {
	Metadata *Metadata `json:"metadata"`
}

// Metadata contains information about a graph API object.
type Metadata struct {
	Type        string            `json:"type"`
	Connections map[string]string `json:"connections"`
	Fields      []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Type        string `json:"type,omitempty"`
	} `json:"fields"`
}

// MinimalResponse contains some information about a object being updated.
type MinimalResponse struct {
	ID          string `json:"id"`
	Success     bool   `json:"success"`
	UpdatedTime Time   `json:"updated_time"`
	ErrorContainer
}

// SummaryContainer contains a summary with a total count of items.
type SummaryContainer struct {
	Summary struct {
		TotalCount uint64 `json:"total_count"`
	} `json:"summary"`
}

type AsyncSession struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type AsyncBatchCreateResponse struct {
	AsyncSessions []AsyncSession `json:"async_sessions"`
}

type AsyncBatchOperation struct {
	Method      string `json:"method"`
	RelativeURL string `json:"relative_url"`
	Name        string `json:"name"`
	Body        string `json:"body"`
}

type AsyncBatchCreateRequest struct {
	AsyncBatch []AsyncBatchOperation `json:"asyncbatch"`
}

type AsyncBatch struct {
	Result    string `json:"result"`
	Status    string `json:"status"`
	ErrorCode int    `json:"error_code"`
	Exception string `json:"exception"`
}

type AdObjectID struct {
	AdObjectType string `json:"ad_object_type"`
	SourceID     string `json:"source_id"`
	CopiedID     string `json:"copied_id"`
}

type CopiedAdsetAsyncBatchResult struct {
	CopiedAdSetID string       `json:"copied_adset_id"`
	AdObjectIDs   []AdObjectID `json:"ad_object_ids"`
}

type BatchRequest struct {
	Method string     `json:"method"`
	Path   string     `json:"relative_url"`
	Body   url.Values `json:"body"`
}

func (br BatchRequest) MarshalJSON() ([]byte, error) {
	type Alias BatchRequest

	return json.Marshal(&struct {
		Body string `json:"body"`
		*Alias
	}{
		Body:  br.Body.Encode(),
		Alias: (*Alias)(&br),
	})
}

type BatchResponse struct {
	Code int `json:"code"`
	Body any `json:"body"`
}

func (br *BatchResponse) UnmarshalJSON(data []byte) error {
	temp := struct {
		Code int    `json:"code"`
		Body string `json:"body"`
	}{}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	var body any

	if err := json.Unmarshal([]byte(temp.Body), &body); err != nil {
		return err
	}

	br.Code = temp.Code
	br.Body = body

	return nil
}
