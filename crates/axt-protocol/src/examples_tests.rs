//! The generated example types against their descriptions, ported from
//! `test/examples_test.dart` of `axt_protocol` for Dart: a value built from a struct goes
//! to its `Value`, is written and read with the type's schema and checked as a received
//! record is, and comes back as the same struct.

use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};

use crate::examples::*;
use crate::record_decoder::decode_record;
use crate::{Error, ErrorCode, TypeDescription, Value};

fn floating(year: i32, month: i32, day: i32, hour: i32) -> AxtDateTime {
    AxtDateTime {
        year,
        month,
        day,
        hour,
        minute: 30,
        second: 0,
        millisecond: 0,
        zone: None,
        offset_seconds: None,
        instant_ms: None,
    }
}

/// 2027-03-01 10:00 in Europe/Berlin.
fn zoned() -> AxtDateTime {
    AxtDateTime {
        year: 2027,
        month: 3,
        day: 1,
        hour: 10,
        minute: 0,
        second: 0,
        millisecond: 0,
        zone: Some("Europe/Berlin".into()),
        offset_seconds: Some(3600),
        instant_ms: Some(1_803_891_600_000),
    }
}

fn relations() -> Vec<AxtRelation> {
    vec![
        AxtRelation {
            id: "0f8fad5b-d9cb-469f-a165-70867728950e".into(),
            kind: "axt.related".into(),
            target: AxtRelationTarget::RelationRecordTarget(AxtRelationRecordTarget {
                id: "7c9e6679-7425-40de-944b-e07fc1f90ae7".into(),
                sender: None,
                r#type: "axt.example.v1.Pet".into(),
                text: "Minka".into(),
            }),
            note: String::new(),
            start: Some(floating(2020, 5, 3, 0)),
            end: None,
            attributes: BTreeMap::new(),
        },
        AxtRelation {
            id: "1b4e28ba-2fa1-41d2-883f-0016d3cca427".into(),
            kind: "org.example.catalog.patient".into(),
            target: AxtRelationTarget::RelationRecordTarget(AxtRelationRecordTarget {
                id: "6ba7b810-9dad-41d1-80b4-00c04fd430c8".into(),
                sender: Some([7; 32]),
                r#type: String::new(),
                text: String::new(),
            }),
            note: "Seen twice.".into(),
            start: None,
            end: Some(zoned()),
            attributes: BTreeMap::new(),
        },
        AxtRelation {
            id: "3f2504e0-4f89-41d3-9a0c-0305e82c3301".into(),
            kind: "axt.related".into(),
            target: AxtRelationTarget::RelationOutsideTarget(AxtRelationOutsideTarget {
                uri: "https://example.org/vet".into(),
                text: "The vet".into(),
            }),
            note: String::new(),
            start: None,
            end: None,
            attributes: BTreeMap::from([("room".into(), "2".into()), ("floor".into(), "1".into())]),
        },
    ]
}

fn extensions() -> Vec<AxtExtension> {
    let mut data = vec![0xc3, 0x01];
    data.extend([0; 8]);
    vec![AxtExtension {
        name: "org.example.catalog.CatExtension".into(),
        data,
    }]
}

fn appointment() -> Appointment {
    Appointment {
        title: "Vet".into(),
        start: zoned(),
        end: Some(zoned()),
        all_day: false,
        location: "Main Street 1".into(),
        notes: "Bring the card.\nAnd the cat.".into(),
        reminders: vec![
            AxtDuration {
                months: 0,
                days: 0,
                millis: -900_000,
            },
            AxtDuration {
                months: 0,
                days: -1,
                millis: 0,
            },
        ],
        relations: relations(),
        extensions: extensions(),
    }
}

fn car() -> Car {
    Car {
        make: "Volvo".into(),
        model: "V60".into(),
        year: Some(2019),
        plate: "B-AX 123".into(),
        vin: String::new(),
        odometer: Some(120_000),
        odometer_unit: CarDistanceUnit::Kilometre,
        notes: String::new(),
        relations: relations(),
        extensions: vec![],
    }
}

fn document() -> Document {
    Document {
        title: "Invoice".into(),
        file_name: "invoice.pdf".into(),
        media_type: "application/pdf".into(),
        content: vec![0x25, 0x50, 0x44, 0x46],
        dated: Some(AxtDate {
            year: Some(2026),
            month: Some(11),
            day: None,
        }),
        notes: String::new(),
        relations: vec![],
        extensions: extensions(),
    }
}

fn measurement() -> Measurement {
    Measurement {
        quantity: "weight".into(),
        value: 4.25,
        unit: "kg".into(),
        measured_at: floating(2026, 11, 23, 8),
        subject: "Minka".into(),
        notes: String::new(),
        relations: relations(),
        extensions: extensions(),
    }
}

fn note() -> Note {
    Note {
        title: "Shopping".into(),
        text: "# Milk".into(),
        format: NoteFormat::Markdown,
        created: Some(zoned()),
        updated: None,
        tags: vec!["home".into(), "food".into()],
        relations: relations(),
        extensions: vec![],
    }
}

fn person() -> Person {
    Person {
        display_name: "Ada Lovelace".into(),
        prefix: String::new(),
        given_name: "Ada".into(),
        middle_name: String::new(),
        family_name: "Lovelace".into(),
        suffix: String::new(),
        birthday: Some(AxtDate {
            year: None,
            month: Some(12),
            day: Some(10),
        }),
        phones: vec![PersonPhone {
            label: "home".into(),
            number: "+44 20 7946 0000".into(),
        }],
        emails: vec![PersonEmail {
            label: "work".into(),
            address: "ada@example.org".into(),
        }],
        addresses: vec![PersonAddress {
            label: "home".into(),
            street: "St James's Square 12".into(),
            postal_code: "SW1Y 4JH".into(),
            locality: "London".into(),
            region: String::new(),
            country: "GB".into(),
        }],
        notes: String::new(),
        relations: relations(),
        extensions: extensions(),
    }
}

fn pet() -> Pet {
    Pet {
        name: "Minka".into(),
        species: "cat".into(),
        breed: "Maine Coon".into(),
        sex: PetSex::Female,
        neutered: Some(true),
        birthday: Some(AxtDate {
            year: Some(2020),
            month: Some(5),
            day: Some(3),
        }),
        microchip: String::new(),
        notes: String::new(),
        relations: relations(),
        extensions: extensions(),
    }
}

fn task() -> Task {
    Task {
        title: "Vaccinate".into(),
        notes: String::new(),
        due: Some(floating(2027, 1, 1, 0)),
        due_all_day: true,
        repeat: Some("FREQ=YEARLY".into()),
        done: false,
        done_at: None,
        priority: TaskPriority::High,
        relations: vec![],
        extensions: vec![],
    }
}

/// Sends `typed` to its `Value`, writes and reads it with the schema of `description` as a
/// received record, checked, and converts it back.
fn round_trip<T>(typed: T, description: fn() -> Result<TypeDescription, Error>)
where
    T: Clone + PartialEq + Debug + Into<Value> + TryFrom<Value, Error = Error>,
{
    let description = description().unwrap();
    let schema = description.schema();
    let value: Value = typed.clone().into();
    let body = schema.encode_single_object(&value).unwrap();
    let read = decode_record(schema, None, &body, true).unwrap();
    assert_eq!(read, value);
    assert_eq!(T::try_from(read).unwrap(), typed);
}

/// `typed` with its lists and optional fields empty.
fn emptied(value: Value) -> Value {
    match value {
        Value::Record(fields) => Value::Record(
            fields
                .into_iter()
                .map(|(name, v)| {
                    let v = match v {
                        Value::Array(_) => Value::Array(vec![]),
                        Value::Map(_) => Value::Map(BTreeMap::new()),
                        // The required time values stay; every other record is optional.
                        Value::Record(_) if name == "start" || name == "measured_at" => v,
                        Value::Record(_) | Value::Null => Value::Null,
                        other => other,
                    };
                    (name, v)
                })
                .collect(),
        ),
        other => other,
    }
}

fn round_trips<T>(typed: T, description: fn() -> Result<TypeDescription, Error>)
where
    T: Clone + PartialEq + Debug + Into<Value> + TryFrom<Value, Error = Error>,
{
    round_trip(typed.clone(), description);
    let empty = T::try_from(emptied(typed.into())).unwrap();
    round_trip(empty, description);
}

#[test]
fn every_example_type_goes_to_its_value_and_back() {
    round_trips(appointment(), Appointment::description);
    round_trips(car(), Car::description);
    round_trips(document(), Document::description);
    round_trips(measurement(), Measurement::description);
    round_trips(note(), Note::description);
    round_trips(person(), Person::description);
    round_trips(pet(), Pet::description);
    round_trips(task(), Task::description);
}

#[test]
fn every_description_is_valid_and_of_its_type() {
    for (description, name) in [
        (Appointment::description(), "Appointment"),
        (Car::description(), "Car"),
        (Document::description(), "Document"),
        (Measurement::description(), "Measurement"),
        (Note::description(), "Note"),
        (Person::description(), "Person"),
        (Pet::description(), "Pet"),
        (Task::description(), "Task"),
    ] {
        assert_eq!(
            description.unwrap().name(),
            format!("axt.example.v1.{name}")
        );
    }
}

#[test]
fn the_check_of_a_received_record_sees_the_rules_of_relations() {
    let mut pet = pet();
    pet.relations[0].id = "not a uuid".into();
    let description = Pet::description().unwrap();
    let body = description
        .schema()
        .encode_single_object(&pet.into())
        .unwrap();
    let e = decode_record(description.schema(), None, &body, true).unwrap_err();
    assert_eq!(e.code(), Some(ErrorCode::ValueInvalid));
}

fn hash_of(value: &impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn same<T: Clone + PartialEq + Debug + Hash>(value: &T) {
    let copy = value.clone();
    assert_eq!(&copy, value);
    assert_eq!(hash_of(&copy), hash_of(value));
    assert_eq!(format!("{copy:?}"), format!("{value:?}"));
}

#[test]
fn every_type_compares_hashes_shows_and_copies_itself() {
    same(&appointment());
    same(&car());
    same(&document());
    same(&note());
    same(&person());
    same(&pet());
    same(&task());
    for relation in relations() {
        same(&relation);
        same(&relation.target);
    }
    same(&extensions());
    let m = measurement();
    assert_eq!(m.clone(), m);
    assert_eq!(format!("{:?}", m.clone()), format!("{m:?}"));
}

#[test]
fn lists_and_maps_that_differ_are_not_equal() {
    let a = appointment();
    let mut shorter = a.clone();
    shorter.reminders.remove(0);
    assert_ne!(shorter, a);
    let mut reversed = a.clone();
    reversed.reminders.reverse();
    assert_ne!(reversed, a);
    let relation = relations().remove(2);
    let mut more = relation.clone();
    more.attributes.insert("x".into(), "y".into());
    assert_ne!(more, relation);
    let mut one = relation.clone();
    one.attributes = BTreeMap::from([("a".into(), "b".into())]);
    let mut other = relation;
    other.attributes = BTreeMap::from([("c".into(), "b".into())]);
    assert_ne!(one, other);
}

fn invalid<T: TryFrom<Value, Error = Error> + Debug>(value: Value) -> String {
    let e = T::try_from(value).unwrap_err();
    assert_eq!(e.code(), Some(ErrorCode::ValueInvalid));
    e.to_string()
}

#[test]
fn a_value_that_is_not_of_the_type_is_no_struct() {
    // A target of no branch is no relation.
    let Value::Record(mut fields) = Value::from(relations().remove(0)) else {
        panic!("a relation is a record");
    };
    fields[2].1 = Value::Union {
        index: 0,
        branch: "axt.Nope".into(),
        value: Box::new(Value::Record(vec![])),
    };
    assert!(invalid::<AxtRelation>(Value::Record(fields.clone())).contains("axt.Relation.target"));
    fields[2].1 = Value::Null;
    invalid::<AxtRelation>(Value::Record(fields));
    invalid::<Pet>(Value::Null);
    let Value::Record(mut fields) = Value::from(pet()) else {
        panic!("a pet is a record");
    };
    fields.remove(0);
    assert!(invalid::<Pet>(Value::Record(fields)).contains("axt.example.v1.Pet.name"));
    let wrong = |name: &str, value: Value| {
        let Value::Record(fields) = Value::from(pet()) else {
            panic!("a pet is a record");
        };
        Value::Record(
            fields
                .into_iter()
                .map(|(n, v)| {
                    if n == name {
                        (n, value.clone())
                    } else {
                        (n, v)
                    }
                })
                .collect(),
        )
    };
    for (name, value) in [
        ("name", Value::Int(1)),
        ("neutered", Value::String("yes".into())),
        ("sex", Value::String("FEMALE".into())),
        (
            "sex",
            Value::Enum {
                index: 9,
                symbol: "NOPE".into(),
            },
        ),
        ("birthday", Value::Array(vec![])),
        ("relations", Value::Map(BTreeMap::new())),
        ("extensions", Value::Array(vec![Value::Null])),
    ] {
        invalid::<Pet>(wrong(name, value));
    }
    let Value::Record(mut fields) = Value::from(AxtRelationRecordTarget {
        id: String::new(),
        sender: Some([1; 32]),
        r#type: String::new(),
        text: String::new(),
    }) else {
        panic!("a target is a record");
    };
    fields[1].1 = Value::Fixed(vec![1; 31]);
    invalid::<AxtRelationRecordTarget>(Value::Record(fields.clone()));
    fields[1].1 = Value::Bytes(vec![1; 32]);
    invalid::<AxtRelationRecordTarget>(Value::Record(fields));
    invalid::<AxtRelation>(Value::from(appointment()));
    let mut attributes = BTreeMap::new();
    attributes.insert("k".to_owned(), Value::Int(1));
    let Value::Record(mut fields) = Value::from(relations().remove(2)) else {
        panic!("a relation is a record");
    };
    fields[6].1 = Value::Map(attributes);
    invalid::<AxtRelation>(Value::Record(fields));
    for value in [
        Value::Long(1),
        Value::Float(1.0),
        Value::Double(1.0),
        Value::Bytes(vec![]),
        Value::Boolean(true),
    ] {
        invalid::<AxtDuration>(value.clone());
        invalid::<AxtRelationTarget>(value.clone());
        invalid::<TaskPriority>(value);
    }
    let Value::Record(mut fields) = Value::from(measurement()) else {
        panic!("a measurement is a record");
    };
    fields[1].1 = Value::Float(1.0);
    invalid::<Measurement>(Value::Record(fields));
    let Value::Record(mut fields) = Value::from(car()) else {
        panic!("a car is a record");
    };
    fields[5].1 = Value::Int(1);
    invalid::<Car>(Value::Record(fields));
    let Value::Record(mut fields) = Value::from(task()) else {
        panic!("a task is a record");
    };
    fields[3].1 = Value::Int(1);
    invalid::<Task>(Value::Record(fields));
    let Value::Record(mut fields) = Value::from(document()) else {
        panic!("a document is a record");
    };
    fields[3].1 = Value::String(String::new());
    invalid::<Document>(Value::Record(fields));
}

#[test]
fn enums_know_their_symbols_and_no_other() {
    fn check<T>(all: &[T], symbol: fn(T) -> &'static str, from_symbol: fn(&str) -> Option<T>)
    where
        T: Copy + PartialEq + Debug + Into<Value> + TryFrom<Value, Error = Error>,
    {
        for (index, &value) in all.iter().enumerate() {
            assert_eq!(from_symbol(symbol(value)), Some(value));
            assert_eq!(
                value.into(),
                Value::Enum {
                    index: u32::try_from(index).unwrap(),
                    symbol: symbol(value).into(),
                }
            );
            assert_eq!(T::try_from(value.into()).unwrap(), value);
        }
        assert_eq!(from_symbol("NOPE"), None);
    }
    check(
        &CarDistanceUnit::ALL,
        CarDistanceUnit::symbol,
        CarDistanceUnit::from_symbol,
    );
    check(
        &NoteFormat::ALL,
        NoteFormat::symbol,
        NoteFormat::from_symbol,
    );
    check(&PetSex::ALL, PetSex::symbol, PetSex::from_symbol);
    check(
        &TaskPriority::ALL,
        TaskPriority::symbol,
        TaskPriority::from_symbol,
    );
    assert_eq!(TaskPriority::None.symbol(), "NONE");
}
