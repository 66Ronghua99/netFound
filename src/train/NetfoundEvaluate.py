import os
import numpy as np
import torch

from dataclasses import dataclass
from torch.distributed.elastic.multiprocessing.errors import record

from transformers import (
    HfArgumentParser,
    TrainingArguments,
    EvalPrediction,
)

from sklearn.metrics import (
    f1_score,
    accuracy_score,
    precision_score,
    recall_score,
    top_k_accuracy_score,
    classification_report,
    confusion_matrix,
)

from NetFoundDataCollator import DataCollatorForFlowClassification
from NetFoundModels import NetfoundFinetuningModel, NetfoundNoPTM
from NetFoundTrainer import NetfoundTrainer
from NetfoundConfig import NetfoundConfig, NetFoundTCPOptionsConfig, NetFoundLarge
from NetfoundTokenizer import NetFoundTokenizer
from utils import (
    ModelArguments,
    CommonDataTrainingArguments,
    load_train_test_datasets,
    get_90_percent_cpu_count,
    get_logger,
    freeze,
)


logger = get_logger(name=__name__)


@dataclass
class EvalDataArgs(CommonDataTrainingArguments):
    num_labels: int | None = None
    problem_type: str | None = None  # "regression" or "single_label_classification"
    netfound_large: bool = False


def regression_metrics(p: EvalPrediction):
    logits = p.predictions[0] if isinstance(p.predictions, tuple) else p.predictions
    label_ids = p.label_ids.astype(int)
    return {"loss": np.mean(np.absolute((logits - label_ids)))}


def classif_metrics(p: EvalPrediction, num_classes: int):
    logits = p.predictions[0] if isinstance(p.predictions, tuple) else p.predictions
    label_ids = p.label_ids.astype(int)
    weighted_f1 = f1_score(
        y_true=label_ids, y_pred=logits.argmax(axis=1), average="weighted", zero_division=0
    )
    weighted_prec = precision_score(
        y_true=label_ids, y_pred=logits.argmax(axis=1), average="weighted", zero_division=0
    )
    weighted_recall = recall_score(
        y_true=label_ids, y_pred=logits.argmax(axis=1), average="weighted", zero_division=0
    )
    accuracy = accuracy_score(y_true=label_ids, y_pred=logits.argmax(axis=1))
    logger.warning(classification_report(label_ids, logits.argmax(axis=1), digits=5))
    logger.warning(confusion_matrix(label_ids, logits.argmax(axis=1)))
    if num_classes > 3:
        logger.warning(f"top3:{top_k_accuracy_score(label_ids, logits, k=3, labels=np.arange(num_classes))}")
    if num_classes > 5:
        logger.warning(f"top5:{top_k_accuracy_score(label_ids, logits, k=5, labels=np.arange(num_classes))}")
    if num_classes > 10:
        logger.warning(f"top10:{top_k_accuracy_score(label_ids, logits, k=10, labels=np.arange(num_classes))}")
    return {
        "weighted_f1": weighted_f1,
        "accuracy": accuracy,
        "weighted_prec: ": weighted_prec,
        "weighted_recall": weighted_recall,
    }


@record
def main():
    parser = HfArgumentParser((ModelArguments, EvalDataArgs, TrainingArguments))
    model_args, data_args, training_args = parser.parse_args_into_dataclasses()

    logger.info(f"model_args: {model_args}")
    logger.info(f"data_args: {data_args}")
    logger.info(f"training_args: {training_args}")

    # Load datasets (we only need the test split for evaluation)
    train_dataset, test_dataset = load_train_test_datasets(logger, data_args)

    # Build config consistent with finetuning
    config_cls = NetFoundTCPOptionsConfig if data_args.tcpoptions else NetfoundConfig
    config = config_cls(
        num_hidden_layers=model_args.num_hidden_layers,
        num_attention_heads=model_args.num_attention_heads,
        hidden_size=model_args.hidden_size,
        no_meta=data_args.no_meta,
        flat=data_args.flat,
    )
    if data_args.netfound_large:
        large_cfg = NetFoundLarge()
        config.hidden_size = large_cfg.hidden_size
        config.num_hidden_layers = large_cfg.num_hidden_layers
        config.num_attention_heads = large_cfg.num_attention_heads

    config.pretraining = False
    config.num_labels = data_args.num_labels
    config.problem_type = data_args.problem_type

    # Tokenizer for evaluation and dataset mapping
    testing_tokenizer = NetFoundTokenizer(config=config)

    map_params = {"batched": True}
    map_params_stream = {}
    if not data_args.streaming:
        map_params["num_proc"] = data_args.preprocessing_num_workers or get_90_percent_cpu_count()
    logger.warning("Tokenizing evaluation dataset ...")
    test_dataset = test_dataset.map(function=testing_tokenizer, **map_params)

    # Data collator
    data_collator = DataCollatorForFlowClassification(config.max_burst_length)

    # Load model
    if model_args.model_name_or_path is not None and os.path.exists(model_args.model_name_or_path):
        logger.warning(f"Loading fine-tuned weights from {model_args.model_name_or_path}")
        model = freeze(NetfoundFinetuningModel.from_pretrained(model_args.model_name_or_path, config=config), model_args)
    elif model_args.no_ptm:
        model = NetfoundNoPTM(config=config)
    else:
        model = freeze(NetfoundFinetuningModel(config=config), model_args)

    # Metrics
    if data_args.problem_type == "regression":
        compute_metrics = regression_metrics
    else:
        compute_metrics = lambda p: classif_metrics(p, data_args.num_labels)

    # Trainer for evaluation only
    trainer = NetfoundTrainer(
        model=model,
        args=training_args,
        train_dataset=None,
        eval_dataset=test_dataset,
        tokenizer=testing_tokenizer,
        compute_metrics=compute_metrics,
        data_collator=data_collator,
    )

    # Evaluate
    logger.warning("*** Evaluate (fine-tuned model) ***")
    metrics = trainer.evaluate(eval_dataset=test_dataset)
    trainer.log_metrics("eval", metrics)
    trainer.save_metrics("eval", metrics)


if __name__ == "__main__":
    main()


