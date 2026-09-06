import os
import math
import joblib
import psycopg
import pandas as pd
import numpy as np


DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set")


# =========================================================
# MODEL PATHS
# =========================================================

MODEL_DIR = "models"

WORLDWIDE_RAW_PATH = os.path.join(
    MODEL_DIR,
    "worldwide_v3_raw.joblib"
)

WORLDWIDE_LOG_PATH = os.path.join(
    MODEL_DIR,
    "worldwide_v3_log.joblib"
)

INDIA_RAW_PATH = os.path.join(
    MODEL_DIR,
    "india_v1_raw.joblib"
)

INDIA_LOG_PATH = os.path.join(
    MODEL_DIR,
    "india_v1_log.joblib"
)

OVERSEAS_RAW_PATH = os.path.join(
    MODEL_DIR,
    "overseas_v1_raw.joblib"
)

OVERSEAS_LOG_PATH = os.path.join(
    MODEL_DIR,
    "overseas_v1_log.joblib"
)


# =========================================================
# PRODUCTION MODEL CONFIGURATION
# =========================================================

# Worldwide V3 validation-selected blend
WORLDWIDE_RAW_WEIGHT = 0.10
WORLDWIDE_LOG_WEIGHT = 0.90

# India V1 validation selected pure LOG
INDIA_RAW_WEIGHT = 0.00
INDIA_LOG_WEIGHT = 1.00

# Overseas V1 validation selected pure LOG
OVERSEAS_RAW_WEIGHT = 0.00
OVERSEAS_LOG_WEIGHT = 1.00


# =========================================================
# LOAD MODELS ONCE
# =========================================================

print("Loading BoxOfficeX AI models...")

worldwide_raw_model = joblib.load(
    WORLDWIDE_RAW_PATH
)

worldwide_log_model = joblib.load(
    WORLDWIDE_LOG_PATH
)

india_raw_model = joblib.load(
    INDIA_RAW_PATH
)

india_log_model = joblib.load(
    INDIA_LOG_PATH
)

overseas_raw_model = joblib.load(
    OVERSEAS_RAW_PATH
)

overseas_log_model = joblib.load(
    OVERSEAS_LOG_PATH
)

print("BoxOfficeX AI models loaded.")


# =========================================================
# EXACT WORLDWIDE V3 FEATURES
# =========================================================

WORLDWIDE_FEATURES = [
    "release_year",
    "release_month",
    "release_weekday",

    "budget_crore",

    "cast_power",
    "cast_power_confidence",

    "director_power",
    "director_confidence",

    "budget_known",
    "cast_power_known",
    "director_power_known",

    "language",
    "industry",
    "genre"
]


# =========================================================
# INDIA / OVERSEAS FEATURES
# =========================================================

MARKET_FEATURES = [
    "release_year",
    "release_month",
    "release_weekday",

    "log_budget",
    "budget_known",

    "cast_power",
    "cast_power_confidence",
    "cast_power_known",

    "director_power",
    "director_confidence",
    "director_power_known",

    "is_franchise",
    "is_sequel",
    "installment_number",
    "franchise_power",

    "language",
    "industry",
    "genre"
]


# =========================================================
# FETCH MOVIE FEATURES
# =========================================================

def get_movie_features(movie_id):

    query = """
    SELECT
        m.id AS movie_id,
        m.title,
        m.release_date,

        COALESCE(
            m.release_year,
            EXTRACT(YEAR FROM m.release_date)::int
        ) AS release_year,

        EXTRACT(
            MONTH FROM m.release_date
        )::int AS release_month,

        EXTRACT(
            DOW FROM m.release_date
        )::int AS release_weekday,

        LOWER(
            COALESCE(m.language, 'unknown')
        ) AS language,

        LOWER(
            COALESCE(m.industry, 'unknown')
        ) AS industry,

        LOWER(
            COALESCE(m.genre, 'unknown')
        ) AS genre,

        NULLIF(
            m.budget_crore,
            0
        ) AS budget_crore,

        CASE
            WHEN m.budget_crore > 0
            THEN TRUE
            ELSE FALSE
        END AS budget_known,

        CASE
            WHEN m.budget_crore > 0
            THEN LN(1 + m.budget_crore)
            ELSE NULL
        END AS log_budget,

        COALESCE(
            cp.combined_star_power,
            50
        ) AS cast_power,

        COALESCE(
            cp.avg_confidence,
            0
        ) AS cast_power_confidence,

        CASE
            WHEN cp.movie_id IS NOT NULL
                 AND cp.avg_confidence > 0
            THEN TRUE
            ELSE FALSE
        END AS cast_power_known,

        COALESCE(
            df.historical_director_power,
            50
        ) AS director_power,

        COALESCE(
            df.director_confidence,
            0
        ) AS director_confidence,

        CASE
            WHEN df.movie_id IS NOT NULL
                 AND df.director_confidence > 0
            THEN TRUE
            ELSE FALSE
        END AS director_power_known,

        COALESCE(
            ff.is_franchise,
            FALSE
        ) AS is_franchise,

        COALESCE(
            ff.is_sequel,
            FALSE
        ) AS is_sequel,

        COALESCE(
            ff.installment_number,
            0
        ) AS installment_number,

        COALESCE(
            ff.franchise_power,
            50
        ) AS franchise_power

    FROM movies m

    LEFT JOIN ai_movie_cast_power cp
        ON cp.movie_id = m.id

    LEFT JOIN ai_movie_director_features df
        ON df.movie_id = m.id

    LEFT JOIN ai_movie_franchise_features ff
        ON ff.movie_id = m.id

    WHERE m.id = %s
    LIMIT 1;
    """

    with psycopg.connect(
        DATABASE_URL
    ) as conn:

        df = pd.read_sql(
            query,
            conn,
            params=(movie_id,)
        )

    if df.empty:
        raise ValueError(
            f"Movie ID {movie_id} not found."
        )

    return df.iloc[0].to_dict()


# =========================================================
# CREATE MODEL INPUT
# =========================================================

def create_dataframe(
    movie,
    columns
):

    row = {}

    for column in columns:
        row[column] = movie.get(column)

    return pd.DataFrame([row])


# =========================================================
# SAFE RAW PREDICTION
# =========================================================

def predict_raw(model, X):

    value = float(
        model.predict(X)[0]
    )

    return max(
        0.0,
        value
    )


# =========================================================
# SAFE LOG PREDICTION
# =========================================================

def predict_log(model, X):

    log_value = float(
        model.predict(X)[0]
    )

    value = math.expm1(
        log_value
    )

    return max(
        0.0,
        value
    )


# =========================================================
# CONFIDENCE
# =========================================================

def calculate_confidence(movie):

    score = 0

    # Budget is one of our strongest scale signals
    if movie["budget_known"]:
        score += 30

    # Historical cast information
    if movie["cast_power_known"]:
        score += 30

    # Historical director information
    if movie["director_power_known"]:
        score += 20

    # Franchise information
    if movie["is_franchise"]:
        score += 10

    # Basic categorical information
    if movie["language"] != "unknown":
        score += 5

    if movie["genre"] != "unknown":
        score += 5

    if score >= 75:
        level = "High"

    elif score >= 45:
        level = "Medium"

    else:
        level = "Low"

    return score, level


# =========================================================
# PREDICTION RANGE
# =========================================================

def prediction_range(
    prediction,
    confidence_level,
    market
):

    # V1 calibrated conservative ranges.
    # Later these can be replaced with
    # residual quantiles from larger datasets.

    range_map = {
        "worldwide": {
            "High": 0.30,
            "Medium": 0.40,
            "Low": 0.55
        },

        "india": {
            "High": 0.35,
            "Medium": 0.45,
            "Low": 0.60
        },

        "overseas": {
            "High": 0.40,
            "Medium": 0.55,
            "Low": 0.70
        }
    }

    pct = range_map[
        market
    ][confidence_level]

    low = max(
        0,
        prediction * (1 - pct)
    )

    high = prediction * (
        1 + pct
    )

    return low, high


# =========================================================
# POWER SCORE
# =========================================================

def calculate_power_score(
    movie,
    worldwide_prediction
):

    cast = float(
        movie["cast_power"]
    )

    director = float(
        movie["director_power"]
    )

    franchise = float(
        movie["franchise_power"]
    )

    # Gross potential score
    gross_score = min(
        100,
        (
            math.log1p(
                worldwide_prediction
            ) /
            math.log1p(1000)
        ) * 100
    )

    score = (
        cast * 0.40
        +
        director * 0.20
        +
        franchise * 0.10
        +
        gross_score * 0.30
    )

    return round(
        min(
            100,
            max(
                0,
                score
            )
        ),
        1
    )


# =========================================================
# COMPLETE PREDICTION
# =========================================================

def predict_movie(movie_id):

    movie = get_movie_features(
        movie_id
    )

    worldwide_X = create_dataframe(
        movie,
        WORLDWIDE_FEATURES
    )

    market_X = create_dataframe(
        movie,
        MARKET_FEATURES
    )


    # =====================================================
    # WORLDWIDE V3
    # =====================================================

    worldwide_raw = predict_raw(
        worldwide_raw_model,
        worldwide_X
    )

    worldwide_log = predict_log(
        worldwide_log_model,
        worldwide_X
    )

    worldwide_prediction = (
        WORLDWIDE_RAW_WEIGHT
        * worldwide_raw
        +
        WORLDWIDE_LOG_WEIGHT
        * worldwide_log
    )


    # =====================================================
    # INDIA
    # =====================================================

    india_raw = predict_raw(
        india_raw_model,
        market_X
    )

    india_log = predict_log(
        india_log_model,
        market_X
    )

    india_prediction = (
        INDIA_RAW_WEIGHT
        * india_raw
        +
        INDIA_LOG_WEIGHT
        * india_log
    )


    # =====================================================
    # OVERSEAS
    # =====================================================

    overseas_raw = predict_raw(
        overseas_raw_model,
        market_X
    )

    overseas_log = predict_log(
        overseas_log_model,
        market_X
    )

    overseas_prediction = (
        OVERSEAS_RAW_WEIGHT
        * overseas_raw
        +
        OVERSEAS_LOG_WEIGHT
        * overseas_log
    )


    # =====================================================
    # CONFIDENCE
    # =====================================================

    confidence_score, confidence_level = (
        calculate_confidence(movie)
    )


    # =====================================================
    # RANGES
    # =====================================================

    ww_low, ww_high = prediction_range(
        worldwide_prediction,
        confidence_level,
        "worldwide"
    )

    india_low, india_high = prediction_range(
        india_prediction,
        confidence_level,
        "india"
    )

    overseas_low, overseas_high = prediction_range(
        overseas_prediction,
        confidence_level,
        "overseas"
    )


    # =====================================================
    # POWER SCORE
    # =====================================================

    power_score = calculate_power_score(
        movie,
        worldwide_prediction
    )


    # =====================================================
    # RESPONSE
    # =====================================================

    return {

        "movie_id":
            int(movie["movie_id"]),

        "title":
            movie["title"],

        "model_versions": {
            "worldwide": "WORLDWIDE_V3",
            "india": "INDIA_V1",
            "overseas": "OVERSEAS_V1"
        },

        "power_score":
            power_score,

        "confidence": {
            "score":
                confidence_score,

            "level":
                confidence_level
        },

        "india": {
            "prediction":
                round(
                    india_prediction,
                    2
                ),

            "low":
                round(
                    india_low,
                    2
                ),

            "high":
                round(
                    india_high,
                    2
                )
        },

        "overseas": {
            "prediction":
                round(
                    overseas_prediction,
                    2
                ),

            "low":
                round(
                    overseas_low,
                    2
                ),

            "high":
                round(
                    overseas_high,
                    2
                )
        },

        "worldwide": {
            "prediction":
                round(
                    worldwide_prediction,
                    2
                ),

            "low":
                round(
                    ww_low,
                    2
                ),

            "high":
                round(
                    ww_high,
                    2
                )
        }
    }


# =========================================================
# CMD TEST
# =========================================================

if __name__ == "__main__":

    print()
    print("=" * 80)
    print("BOXOFFICEX AI PREDICTION TEST")
    print("=" * 80)

    movie_id = int(
        input(
            "Enter movie ID: "
        )
    )

    result = predict_movie(
        movie_id
    )

    print()
    print("=" * 80)
    print(result["title"])
    print("=" * 80)

    print(
        "Power Score:",
        result["power_score"],
        "/ 100"
    )

    print(
        "Confidence:",
        result["confidence"]["level"],
        f"({result['confidence']['score']}/100)"
    )

    print()

    print(
        "India:",
        result["india"]["prediction"],
        "Cr",
        "| Range:",
        result["india"]["low"],
        "-",
        result["india"]["high"],
        "Cr"
    )

    print(
        "Overseas:",
        result["overseas"]["prediction"],
        "Cr",
        "| Range:",
        result["overseas"]["low"],
        "-",
        result["overseas"]["high"],
        "Cr"
    )

    print(
        "Worldwide:",
        result["worldwide"]["prediction"],
        "Cr",
        "| Range:",
        result["worldwide"]["low"],
        "-",
        result["worldwide"]["high"],
        "Cr"
    )

    print()
    print(
        "Models:",
        result["model_versions"]
    )

    print("=" * 80)