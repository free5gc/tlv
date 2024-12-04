package tlv

import (
	"encoding"
	"errors"
	"fmt"
	"maps"
	"math"
	"reflect"
	"slices"
	"strconv"
	"sync/atomic"
)

func Unmarshal(b []byte, v any) error {
	// decodeValue shares the bytes of input slice whenever possible
	//   clone protects the client code that is not ready for this
	b = slices.Clone(b)
	return decodeValue(b, v)
}

func UnmarshalZeroCopy(b []byte, v any) error {
	return decodeValue(b, v)
}

func decodeValue(b bytez, v any) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%v > %w", reflect.TypeOf(v), err)
		}
	}()

	if v == nil {
		return errors.New("nil")
	}

	if v, ok := v.(encoding.BinaryUnmarshaler); ok {
		return v.UnmarshalBinary(b)
	}

	switch v := v.(type) {
	case *int8:
		*v, err = b.ReadInt8()
	case *int16:
		*v, err = b.ReadInt16()
	case *int32:
		*v, err = b.ReadInt32()
	case *int64:
		*v, err = b.ReadInt64()
	case *uint8:
		*v, err = b.ReadUint8()
	case *uint16:
		*v, err = b.ReadUint16()
	case *uint32:
		*v, err = b.ReadUint32()
	case *uint64:
		*v, err = b.ReadUint64()
	case *string:
		*v, err = b.ReadString(len(b))
	case *[]byte:
		*v, err = b.ReadSlice(len(b))
	default:
		val := reflect.ValueOf(v)
		if val.Kind() != reflect.Ptr {
			return errors.New("not a pointer")
		}
		val = val.Elem()
		typ := val.Type()
		switch val.Kind() {
		case reflect.Ptr:
			if val.IsNil() {
				val.Set(reflect.New(typ.Elem()))
			}
			if err = decodeValue(b, val.Interface()); err != nil {
				return err
			}
		case reflect.Struct:
			tagMap, err := tagMapFor(typ)
			if err != nil {
				return err
			}

			for len(b) > 0 {
				tag, bytes, err := readTLV(&b)
				if err != nil {
					return err
				}

				idx, ok := tagMap[tag]
				if !ok {
					// return fmt.Errorf("no field has `tlv:%d` tag", tag)
					continue // skip unexpected TLVs
				}

				f := val.Field(idx)

				if f.Kind() == reflect.Ptr && f.IsNil() {
					f.Set(reflect.New(f.Type().Elem()))
				}
				if f.Kind() != reflect.Ptr {
					f = f.Addr()
				}

				err = decodeValue(bytes, f.Interface())
				if err != nil {
					return fmt.Errorf("field %s %w", val.Type().Field(idx).Name, err)
				}
			}
		case reflect.Slice:
			if typ.Elem().Kind() == reflect.Ptr || typ.Elem().Kind() == reflect.Struct || isNumber(typ.Elem()) {
				elemValue := reflect.New(typ.Elem())
				if err := decodeValue(b, elemValue.Interface()); err != nil {
					return err
				}
				val.Set(reflect.Append(val, elemValue.Elem()))
			} else {
				return errors.New("unsupported slice type")
			}
		default:
			return errors.New("unsupported type")
		}
	}

	return nil
}

func readTLV(b *bytez) (tag uint16, value bytez, err error) {
	if tag, err = b.ReadUint16(); err != nil {
		err = fmt.Errorf("%w @ tag", err)
		return
	}
	var length uint16
	if length, err = b.ReadUint16(); err != nil {
		err = fmt.Errorf("%w @ len", err)
		return
	}
	if value, err = b.ReadSlice(int(length)); err != nil {
		err = fmt.Errorf("%w @ value", err)
		return
	}
	return
}

type tagMap map[uint16]int

// type -> tag -> field index
var typeCache atomic.Pointer[map[reflect.Type]tagMap]

func tagMapFor(typ reflect.Type) (tagMap, error) {
	// Cache handling is intentionally racy to keep the cost of access to a single atomic read
	// since the contents are strictly determenistic, it's okay if we rebuild them a few times

	tc := typeCache.Load()
	if tc == nil {
		tc = &map[reflect.Type]tagMap{}
		typeCache.Store(tc)
	}

	t := (*tc)[typ]
	if t == nil {
		t = make(tagMap)
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() {
				return nil, fmt.Errorf("field %s is not exported", field.Name)
			} else if tlv, ok := field.Tag.Lookup("tlv"); !ok {
				return nil, fmt.Errorf("field %s has no `tlv:...` tag", field.Name)
			} else if tlvI, err := strconv.Atoi(tlv); err != nil || tlvI < 0 || tlvI > math.MaxUint16 {
				return nil, fmt.Errorf("field %s has invalid `tlv:%s` tag", field.Name, tlv)
			} else {
				t[uint16(tlvI)] = i
			}
		}
		tc = ref(maps.Clone(*tc))
		(*tc)[typ] = t
		typeCache.Store(tc)
	}

	return t, nil
}
