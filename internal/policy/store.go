package policy

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// Store 保存当前生效策略。Current() 返回的 *Policy 永不为 nil 且不可变，
// 因此进行中的请求只会看到完整的旧版或新版，绝不会看到新旧混合。
type Store struct {
	cur atomic.Pointer[Policy]

	mu        sync.Mutex
	serial    int64
	revision  int
	lastError string
	lastOK    bool
}

// NewStore 以初始策略创建存储；初始策略必须有效，否则返回错误，绝不默认放行。
func NewStore(initial *Policy) (*Store, error) {
	if initial == nil {
		return nil, fmt.Errorf("初始策略不能为空（安全默认：拒绝全部）")
	}
	s := &Store{revision: 1, lastOK: true}
	s.cur.Store(initial)
	return s, nil
}

// Current 返回当前策略快照与修订号。
func (s *Store) Current() (*Policy, int) {
	p := s.cur.Load()
	s.mu.Lock()
	rev := s.revision
	s.mu.Unlock()
	return p, rev
}

// ReloadResult 是一次重载的明确结果。
type ReloadResult struct {
	Success  bool
	Revision int
	Replaced bool
	Reason   string
}

// Reload 解析并原子替换策略。失败时明确返回原因并沿用上一版策略。
func (s *Store) Reload(data []byte) ReloadResult {
	p, err := Parse(data)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serial++
	if err != nil {
		s.lastError = err.Error()
		s.lastOK = false
		return ReloadResult{
			Success:  false,
			Revision: s.revision,
			Reason:   err.Error(),
		}
	}
	s.cur.Store(p)
	s.revision++
	s.lastError = ""
	s.lastOK = true
	return ReloadResult{Success: true, Revision: s.revision, Replaced: true}
}

// ReloadFile 从文件重载。
func (s *Store) ReloadFile(path string) ReloadResult {
	p, err := LoadFile(path)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serial++
	if err != nil {
		s.lastError = err.Error()
		s.lastOK = false
		return ReloadResult{Success: false, Revision: s.revision, Reason: err.Error()}
	}
	s.cur.Store(p)
	s.revision++
	s.lastError = ""
	s.lastOK = true
	return ReloadResult{Success: true, Revision: s.revision, Replaced: true}
}

// Status 报告当前修订号与最近一次重载状态。
func (s *Store) Status() (revision int, lastOK bool, lastError string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revision, s.lastOK, s.lastError
}
